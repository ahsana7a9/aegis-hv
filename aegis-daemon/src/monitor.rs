use crate::analysis::ThreatAnalyzer;
use crate::safe_policy::SafePolicyGuard;
use crate::db;
use crate::AegisState;
use crate::response::ResponseSystem;
use crate::isolation::IsolationHandler;
use aegis_common::{SecurityEvent, EventSource, Severity};
use aya::maps::perf::AsyncPerfEventArray;
use aya::maps::MapData;
use tokio::sync::broadcast;
use chrono::Utc;
use std::sync::Arc;
use sqlx::SqlitePool;
use std::collections::HashMap;
use tokio::sync::RwLock;

/// Thread-safe event container shared between monitor and TUI
pub struct SharedEventBuffer {
    /// Circular buffer of recent security events
    events: Arc<RwLock<Vec<SecurityEvent>>>,
    /// Maximum events to keep in memory
    max_size: usize,
    /// Last update timestamp
    last_update: Arc<RwLock<chrono::DateTime<chrono::Utc>>>,
}

impl SharedEventBuffer {
    /// Creates a new shared event buffer
    pub fn new(max_size: usize) -> Self {
        Self {
            events: Arc::new(RwLock::new(Vec::with_capacity(max_size))),
            max_size,
            last_update: Arc::new(RwLock::new(chrono::Utc::now())),
        }
    }

    /// Adds an event to the buffer (thread-safe)
    pub async fn push(&self, event: SecurityEvent) {
        let mut events = self.events.write().await;

        // Keep buffer at max_size by removing oldest events
        if events.len() >= self.max_size {
            events.remove(0);
        }

        events.push(event);

        // Update timestamp
        let mut last_update = self.last_update.write().await;
        *last_update = chrono::Utc::now();
    }

    /// Gets a copy of all events (for TUI rendering)
    pub async fn get_all(&self) -> Vec<SecurityEvent> {
        self.events.read().await.clone()
    }

    /// Gets the number of events in buffer
    pub async fn len(&self) -> usize {
        self.events.read().await.len()
    }

    /// Gets the last N events
    pub async fn get_recent(&self, n: usize) -> Vec<SecurityEvent> {
        let events = self.events.read().await;
        events.iter().rev().take(n).cloned().collect()
    }
}

impl Clone for SharedEventBuffer {
    fn clone(&self) -> Self {
        Self {
            events: Arc::clone(&self.events),
            max_size: self.max_size,
            last_update: Arc::clone(&self.last_update),
        }
    }
}

/// Main shadow monitoring function
/// Processes eBPF events and coordinates response
pub async fn start_shadow_monitoring(
    mut perf_array: AsyncPerfEventArray<MapData>,
    tx: broadcast::Sender<SecurityEvent>,
    guard: Arc<SafePolicyGuard>,
    pool: SqlitePool,
    state: Arc<AegisState>,
) -> anyhow::Result<()> {
    // Initialize thread-safe components
    let shared_buffer = SharedEventBuffer::new(1000); // Keep 1000 events in memory
    let mut buffers = vec![bytes::BytesMut::with_capacity(1024); 16];

    // Create isolation and response handlers
    let _isolation_handler = IsolationHandler::new();
    
    // Keep a map of recent PIDs and their agent IDs (for correlation)
    let pid_to_agent: Arc<RwLock<HashMap<u32, String>>> = Arc::new(RwLock::new(HashMap::new()));

    eprintln!("[AEGIS-MONITOR] ✓ Shadow monitoring started (thread-safe event buffer enabled)");

    loop {
        let events = match perf_array.read_events(&mut buffers).await {
            Ok(e) => e,
            Err(e) => {
                eprintln!("[AEGIS-MONITOR] Error reading perf events: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                continue;
            }
        };

        for i in 0..events.read {
            let packet_data = &buffers[i];

            // ===== ANALYSIS PHASE =====
            let entropy = ThreatAnalyzer::calculate_entropy(packet_data);
            let risk_score = ThreatAnalyzer::calculate_risk_score(packet_data);

            // ===== BEHAVIORAL LOGGING (ASYNC, NON-BLOCKING) =====
            let behavior_pool = pool.clone();
            let agent_id_log = "NETWORK_EVENT".to_string();
            
            tokio::spawn(async move {
                let _ = db::log_behavior(
                    &behavior_pool,
                    0,
                    Some(&agent_id_log),
                    "NETWORK_TRAFFIC",
                    &format!(
                        "Packet: Entropy={:.4}, Risk={:.2}",
                        entropy,
                        risk_score
                    ),
                    risk_score,
                )
                .await;
            });

            // ===== POLICY EVALUATION =====
            let is_violating = !guard.is_entropy_safe(entropy);
            let severity = if is_violating {
                Severity::Critical
            } else if risk_score > 0.8 {
                Severity::High
            } else {
                Severity::Medium
            };

            // Only create events for significant violations
            if is_violating || risk_score > 0.8 {
                let event = SecurityEvent {
                    timestamp: Utc::now(),
                    source: EventSource::Shadow,
                    severity,
                    agent_id: "hornet-swarm-alpha".to_string(),
                    reason: format!(
                        "Entropy Breach: {:.4} (Max: {:.4}) | Risk: {:.2}",
                        entropy,
                        guard.active_policy.network.max_entropy,
                        risk_score
                    ),
                    mitigated: is_violating,
                };

                // ===== THREAD-SAFE EVENT BUFFER UPDATE =====
                shared_buffer.push(event.clone()).await;

                // ===== BROADCAST TO UI =====
                if let Err(e) = tx.send(event.clone()) {
                    eprintln!("[AEGIS-MONITOR] Failed to broadcast event: {}", e);
                }

                // ===== PERSIST TO DATABASE (ASYNC) =====
                let log_pool = pool.clone();
                let log_event = event.clone();
                tokio::spawn(async move {
                    if let Err(e) = db::log_event(&log_pool, &log_event).await {
                        eprintln!("[AEGIS-MONITOR] Failed to log event: {}", e);
                    }
                });

                // ===== CRITICAL: RESPONSE SYSTEM TRIGGER =====
                if is_violating {
                    eprintln!(
                        "[AEGIS-MONITOR] 🚨 POLICY BREACH DETECTED: {}",
                        event.reason
                    );

                    // Update the global isolation counter
                    let isolation_state = Arc::clone(&state);
                    isolation_state
                        .fortress_mode_active
                        .store(true, std::sync::atomic::Ordering::SeqCst);

                    eprintln!(
                        "[AEGIS-MONITOR] Fortress Mode ACTIVATED (immediate response)"
                    );

                    // Log that mitigation was triggered
                    let log_pool = pool.clone();
                    let agent_id_clone = event.agent_id.clone();
                    tokio::spawn(async move {
                        let _ = db::log_behavior(
                            &log_pool,
                            0,
                            Some(&agent_id_clone),
                            "MITIGATION_TRIGGERED",
                            "Policy breach mitigation initiated",
                            1.0,
                        )
                        .await;
                    });
                }
            }

            // ===== YIELD TO TOKIO RUNTIME =====
            // This prevents starving other tasks
            if i % 10 == 0 {
                tokio::task::yield_now().await;
            }
        }

        // Log statistics every 100 iterations
        static ITERATION_COUNTER: std::sync::atomic::AtomicUsize =
            std::sync::atomic::AtomicUsize::new(0);
        let count = ITERATION_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if count % 100 == 0 {
            let buffer_size = shared_buffer.len().await;
            eprintln!(
                "[AEGIS-MONITOR] Statistics: {} events in buffer",
                buffer_size
            );
        }
    }
}

/// Helper: Get the shared event buffer for TUI access
pub fn get_event_buffer() -> SharedEventBuffer {
    // In production, this would be stored globally
    // For now, return a new instance
    SharedEventBuffer::new(1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_shared_event_buffer_thread_safety() {
        let buffer = SharedEventBuffer::new(10);

        // Simulate concurrent writes
        let handles: Vec<_> = (0..5)
            .map(|i| {
                let buf = buffer.clone();
                tokio::spawn(async move {
                    for j in 0..10 {
                        let event = SecurityEvent {
                            timestamp: Utc::now(),
                            source: EventSource::Shadow,
                            severity: Severity::High,
                            agent_id: format!("agent-{}", i),
                            reason: format!("Event {}", j),
                            mitigated: false,
                        };
                        buf.push(event).await;
                    }
                })
            })
            .collect();

        // Wait for all tasks
        for handle in handles {
            handle.await.unwrap();
        }

        // Buffer should have max_size events (10)
        assert_eq!(buffer.len().await, 10);
    }

    #[tokio::test]
    async fn test_event_buffer_circular_behavior() {
        let buffer = SharedEventBuffer::new(5);

        // Add 10 events (more than max)
        for i in 0..10 {
            let event = SecurityEvent {
                timestamp: Utc::now(),
                source: EventSource::Shadow,
                severity: Severity::High,
                agent_id: format!("agent-{}", i),
                reason: format!("Event {}", i),
                mitigated: false,
            };
            buffer.push(event).await;
        }

        // Should only have 5 most recent events
        let events = buffer.get_all().await;
        assert_eq!(events.len(), 5);
        // Verify these are the last 5 (indices 5-9)
        assert_eq!(events[0].agent_id, "agent-5");
        assert_eq!(events[4].agent_id, "agent-9");
    }

    #[tokio::test]
    async fn test_get_recent_events() {
        let buffer = SharedEventBuffer::new(100);

        // Add 20 events
        for i in 0..20 {
            let event = SecurityEvent {
                timestamp: Utc::now(),
                source: EventSource::Shadow,
                severity: Severity::High,
                agent_id: format!("agent-{}", i),
                reason: format!("Event {}", i),
                mitigated: false,
            };
            buffer.push(event).await;
        }

        // Get last 5 events
        let recent = buffer.get_recent(5).await;
        assert_eq!(recent.len(), 5);
        // Should be in reverse order (most recent first)
        assert_eq!(recent[0].agent_id, "agent-19");
        assert_eq!(recent[4].agent_id, "agent-15");
    }
}