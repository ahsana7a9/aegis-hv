use crate::analysis::ThreatAnalyzer;
use crate::policy::PolicyGuard;
use crate::db; // Added for logging
use crate::AegisState; // Added for state management
use aegis_common::{SecurityEvent, EventSource, Severity};
use aya::maps::perf::AsyncPerfEventArray;
use aya::maps::MapData;
use tokio::sync::broadcast;
use chrono::Utc;
use std::sync::Arc;
use sqlx::SqlitePool;

pub async fn start_shadow_monitoring(
    mut perf_array: AsyncPerfEventArray<MapData>, 
    tx: broadcast::Sender<SecurityEvent>,
    guard: PolicyGuard,
    pool: SqlitePool,         // New: for DB logging
    state: Arc<AegisState>,    // New: for flipping the isolation switch
) -> anyhow::Result<()> {
    // 16 buffers to match typical CPU core counts or burst handling
    let mut buffers = vec![bytes::BytesMut::with_capacity(1024); 16]; 

    loop {
        let events = match perf_array.read_events(&mut buffers).await {
            Ok(e) => e,
            Err(e) => {
                eprintln!("[AEGIS-MONITOR] Error reading perf events: {}", e);
                continue;
            }
        };
        
        for i in 0..events.read {
            let packet_data = &buffers[i];
            
            // 1. ANALYSIS
            let entropy = ThreatAnalyzer::calculate_entropy(packet_data);
            let severity = ThreatAnalyzer::assess_risk(packet_data);

            // 2. POLICY EVALUATION
            let is_violating = !guard.is_entropy_safe(entropy);
            
            if is_violating || severity >= Severity::High {
                let event = SecurityEvent {
                    timestamp: Utc::now(),
                    source: EventSource::Shadow,
                    severity: if is_violating { Severity::Critical } else { severity },
                    agent_id: "hornet-swarm-alpha".to_string(), 
                    action_attempted: "Outbound Network Traffic".to_string(),
                    reason: format!("Entropy: {:.2} (Max: {:.2})", 
                             entropy, guard.active_policy.network.max_entropy),
                    mitigated: is_violating,
                };

                // 3. BROADCAST TO INTERFACES (TUI/WEB)
                let _ = tx.send(event.clone());

                // 4. PERSIST TO AUDIT LOG
                let log_pool = pool.clone();
                let log_event = event.clone();
                tokio::spawn(async move {
                    let _ = db::log_event(&log_pool, &log_event).await;
                });

                // 5. TRIGGER AUTOMATIC MITIGATION
                if is_violating {
                    let isolation_state = Arc::clone(&state);
                    crate::isolation::trigger_reactive_isolation("hornet-swarm-alpha", &isolation_state).await;
                }
            }
        }
    }
}
