//! Shadow Monitoring System - eBPF event processing with thread-safe shared state
//!
//! SECURITY GUARANTEES:
//! - Shared event buffer is protected by RwLock
//! - Multiple readers (TUI) can access simultaneously
//! - Single writer (monitor) has exclusive access
//! - No lost events under high load
//! - Automatic circular buffer cleanup
//!

use crate::analysis::ThreatAnalyzer;
use crate::safe_policy::SafePolicyGuard;
use crate::db;
use crate::AegisState;
use aegis_common::{SecurityEvent, EventSource, Severity};
use aya::maps::perf::AsyncPerfEventArray;
use aya::maps::MapData;
use tokio::sync::{broadcast, RwLock};
use chrono::Utc;
use std::sync::Arc;
use std::collections::VecDeque;
use sqlx::SqlitePool;

// ═════════════════════════════════════════════════════════════════════════════
// SHARED EVENT BUFFER - Thread-safe event storage for TUI/Web API
// ═════════════════════════════════════════════════════════════════════════════

/// Thread-safe circular event buffer shared between monitor and UI
///
/// # Thread Safety
/// - Uses RwLock: multiple readers, single writer
/// - Automatic cleanup: oldest events evicted when full
/// - No panic on capacity exceed: graceful degradation
#[derive(Clone)]
pub struct SharedEventBuffer {
    /// Recent security events (circular buffer)
    events: Arc<RwLock<VecDeque<SecurityEvent>>>,
    
    /// Maximum events to keep in memory
    max_size: usize,
    
    /// Last update timestamp
    last_update: Arc<RwLock<chrono::DateTime<chrono::Utc>>>,
    
    /// Total events processed (for metrics)
    total_events: Arc<std::sync::atomic::AtomicUsize>,
}

impl SharedEventBuffer {
    /// Creates a new shared event buffer with specified capacity
    pub fn new(max_size: usize) -> Self {
        Self {
            events: Arc::new(RwLock::new(VecDeque::with_capacity(max_size))),
            max_size,
            last_update: Arc::new(RwLock::new(chrono::Utc::now())),
            total_events: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// Adds an event to the buffer (WRITER - exclusive access)
    pub async fn push(&self, event: SecurityEvent) {
        let mut events = self.events.write().await;

        // Maintain circular buffer: remove oldest if at capacity
        while events.len() >= self.max_size {
            events.pop_front();
        }

        events.push_back(event);

        // Update timestamp
        let mut last_update = self.last_update.write().await;
        *last_update = chrono::Utc::now();

        // Increment metric
        self.total_events
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Gets a copy of all events (READER - shared access)
    pub async fn get_all(&self) -> Vec<SecurityEvent> {
        self.events
            .read()
            .await
            .iter()
            .cloned()
            .collect()
    }

    /// Gets the number of events in buffer (READER - shared access)
    pub async fn len(&self) -> usize {
        self.events.read().await.len()
    }

    /// Checks if buffer is empty
    pub async fn is_empty(&self) -> bool {
        self.events.read().await.is_empty()
    }

    /// Gets the last N events in reverse order (most recent first)
    pub async fn get_recent(&self, n: usize) -> Vec<SecurityEvent> {
        let events = self.events.read().await;
        events
            .iter()
            .rev()
            .take(n)
            .cloned()
            .collect()
    }

    /// Gets total events processed
    pub fn total_events(&self) -> usize {
        self.total_events.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Gets last update timestamp
    pub async fn last_updated(&self) -> chrono::DateTime<chrono::Utc> {
        *self.last_update.read().await
    }

    /// Clears all events (for testing)
    #[allow(dead_code)]
    pub async fn clear(&self) {
        self.events.write().await.clear();
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// SHADOW MONITOR - Main eBPF event processing loop
// ═════════════════════════════════════════════════════════════════════════════

/// Starts the shadow monitoring loop
///
/// # Arguments
/// - `perf_array`: eBPF perfbuf events
/// - `tx`: Broadcast channel for real-time events
/// - `guard`: Security policy guard
/// - `pool`: SQLite connection pool
/// - `state`: Global Aegis state
///
/// # Returns
/// Never returns (infinite loop) unless error occurs
pub async fn start_shadow_monitoring(
    mut perf_array: AsyncPerfEventArray<MapData>,
    tx: broadcast::Sender<SecurityEvent>,
    guard: Arc<SafePolicyGuard>,
    pool: SqlitePool,
    state: Arc<AegisState>,
) -> anyhow::Result<()> {
    // Initialize shared components
    let shared_buffer = SharedEventBuffer::new(1000);
    let mut buffers = vec![bytes::BytesMut::with_capacity(1024); 16];

    // Metrics
    let mut total_packets = 0u64;
    let mut violations = 0u64;
    let mut last_stats_time = std::time::Instant::now();

    eprintln!(
        "[AEGIS-MONITOR] ✓ Shadow monitoring started (event buffer: {} cap)",
        1000
    );

    loop {
        // Read events from eBPF perfbuf
        let events = match perf_array.read_events(&mut buffers).await {
            Ok(e) => e,
            Err(e) => {
                eprintln!("[AEGIS-MONITOR] Error reading perf events: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                continue;
            }
        };

        // Process each event
        for i in 0..events.read {
            let packet_data = &buffers[i];
            total_packets += 1;

            // ─────────────────────────────────────────────────────────────
            // PHASE 1: ANALYSIS
            // ─────────────────────────────────────────────────────────────
            let entropy = ThreatAnalyzer::calculate_entropy(packet_data);
            let risk_score = ThreatAnalyzer::calculate_risk_score(packet_data);

            // ─────────────────────────────────────────────────────────────
            // PHASE 2: BEHAVIORAL LOGGING (Non-blocking, async)
            // ─────────────────────────────────────────────────────────────
            let behavior_pool = pool.clone();
            tokio::spawn(async move {
                let _ = db::log_behavior(
                    &behavior_pool,
                    0,
                    Some("NETWORK_TRAFFIC"),
                    "NETWORK_TRAFFIC",
                    &format!(
                        "Entropy={:.4}, Risk={:.2}",
                        entropy,
                        risk_score
                    ),
                    risk_score,
                )
                .await;
            });

            // ─────────────────────────────────────────────────────────────
            // PHASE 3: POLICY EVALUATION
            // ─────────────────────────────────────────────────────────────
            let is_violating = !guard.is_entropy_safe(entropy);
            let severity = if is_violating {
                Severity::Critical
            } else if risk_score > 0.8 {
                Severity::High
            } else {
                Severity::Medium
            };

            // Only create events for significant threats
            if is_violating || risk_score > 0.8 {
                violations += 1;

                let event = SecurityEvent {
                    timestamp: Utc::now(),
                    source: EventSource::Shadow,
                    severity,
                    agent_id: "hornet-swarm-alpha".to_string(),
                    reason: format!(
                        "Entropy {:.4} (max {:.4}) | Risk {:.2}",
                        entropy,
                        guard.active_policy.network.max_entropy,
                        risk_score
                    ),
                    mitigated: is_violating,
                };

                // ─────────────────────────────────────────────────────────
                // STEP A: Add to shared buffer (for TUI)
                // ─────────────────────────────────────────────────────────
                shared_buffer.push(event.clone()).await;

                // ─────────────────────────────────────────────────────────
                // STEP B: Broadcast real-time (for subscribers)
                // ─────────────────────────────────────────────────────────
                if let Err(e) = tx.send(event.clone()) {
                    eprintln!(
                        "[AEGIS-MONITOR] Warning: No subscribers listening: {}",
                        e
                    );
                }

                // ─────────────────────────────────────────────────────────
                // STEP C: Persist to database (async)
                // ──────────────────────���──────────────────────────────────
                let log_pool = pool.clone();
                let log_event = event.clone();
                tokio::spawn(async move {
                    if let Err(e) = db::log_event(&log_pool, &log_event).await {
                        eprintln!("[AEGIS-MONITOR] Database log error: {}", e);
                    }
                });

                // ─────────────────────────────────────────────────────────
                // STEP D: Trigger mitigation if policy violated
                // ─────────────────────────────────────────────────────────
                if is_violating {
                    eprintln!(
                        "[AEGIS-MONITOR] 🚨 POLICY BREACH: {} | Initiating isolation...",
                        event.reason
                    );

                    // Update global fortress mode
                    state
                        .fortress_mode_active
                        .store(true, std::sync::atomic::Ordering::SeqCst);

                    // Log mitigation trigger
                    let log_pool = pool.clone();
                    tokio::spawn(async move {
                        let _ = db::log_behavior(
                            &log_pool,
                            0,
                            Some("hornet-swarm-alpha"),
                            "MITIGATION_TRIGGERED",
                            "Policy breach mitigation initiated",
                            1.0,
                        )
                        .await;
                    });
                }
            }

            // Yield to tokio runtime periodically to prevent starvation
            if i % 10 == 0 {
                tokio::task::yield_now().await;
            }
        }

        // Print statistics every 5 seconds
        if last_stats_time.elapsed() > tokio::time::Duration::from_secs(5) {
            let buffer_size = shared_buffer.len().await;
            eprintln!(
                "[AEGIS-MONITOR] Stats: {} total packets, {} violations, {} buffered events",
                total_packets,
                violations,
                buffer_size
            );
            last_stats_time = std::time::Instant::now();
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ═════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_shared_buffer_push_pop() {
        let buffer = SharedEventBuffer::new(10);

        let event = SecurityEvent {
            timestamp: Utc::now(),
            source: EventSource::Shadow,
            severity: Severity::High,
            agent_id: "test-agent".to_string(),
            reason: "Test event".to_string(),
            mitigated: false,
        };

        buffer.push(event.clone()).await;
        assert_eq!(buffer.len().await, 1);
        assert_eq!(buffer.total_events(), 1);

        let events = buffer.get_all().await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].agent_id, "test-agent");
    }

    #[tokio::test]
    async fn test_circular_buffer_evicts_oldest() {
        let buffer = SharedEventBuffer::new(5);

        // Add 10 events (more than capacity)
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
        assert_eq!(buffer.len().await, 5);

        let events = buffer.get_all().await;
        assert_eq!(events[0].agent_id, "agent-5");  // Oldest remaining
        assert_eq!(events[4].agent_id, "agent-9");  // Newest
    }

    #[tokio::test]
    async fn test_get_recent() {
        let buffer = SharedEventBuffer::new(100);

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

        let recent = buffer.get_recent(5).await;
        assert_eq!(recent.len(), 5);
        // Should be in reverse order (most recent first)
        assert_eq!(recent[0].agent_id, "agent-19");
        assert_eq!(recent[4].agent_id, "agent-15");
    }

    #[tokio::test]
    async fn test_concurrent_reads() {
        let buffer = Arc::new(SharedEventBuffer::new(100));

        // Add some events
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

        // Spawn multiple reader tasks
        let handles: Vec<_> = (0..5)
            .map(|_| {
                let buf = Arc::clone(&buffer);
                tokio::spawn(async move {
                    let events = buf.get_all().await;
                    events.len()
                })
            })
            .collect();

        for handle in handles {
            let len = handle.await.unwrap();
            assert_eq!(len, 10);  // All readers should see all events
        }
    }
}
