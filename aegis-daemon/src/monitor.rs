use crate::analysis::ThreatAnalyzer;
use crate::policy::PolicyGuard;
use crate::db; 
use crate::AegisState; 
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
    guard: Arc<PolicyGuard>,      // Changed to Arc for thread-safe sharing
    pool: SqlitePool,             
    state: Arc<AegisState>,       
) -> anyhow::Result<()> {
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
            
            // 1. ANALYSIS: Behavioral & Entropy
            let entropy = ThreatAnalyzer::calculate_entropy(packet_data);
            let risk_score = ThreatAnalyzer::calculate_risk_score(packet_data); // Heuristic score

            // 2. BEHAVIORAL LOGGING (The "Black Box" Trace)
            // We log every significant event to the behavior table regardless of violation
            let behavior_pool = pool.clone();
            tokio::spawn(async move {
                let _ = db::log_behavior(
                    &behavior_pool, 
                    0, // In production, extract PID from packet metadata
                    "NETWORK_TRAFFIC", 
                    &format!("Packet captured; Entropy: {:.4}", entropy),
                    risk_score
                ).await;
            });

            // 3. POLICY EVALUATION
            let is_violating = !guard.is_entropy_safe(entropy);
            
            if is_violating || risk_score > 0.8 {
                let event = SecurityEvent {
                    timestamp: Utc::now(),
                    source: EventSource::Shadow,
                    severity: if is_violating { Severity::Critical } else { Severity::High },
                    agent_id: "hornet-swarm-alpha".to_string(), 
                    reason: format!("Entropy Breach: {:.2} (Max: {:.2})", 
                             entropy, guard.active_policy.network.max_entropy),
                    mitigated: is_violating,
                };

                // 4. BROADCAST TO UI (TUI/Web Dashboard)
                let _ = tx.send(event.clone());

                // 5. PERSIST TO SECURITY LOG (The "Alert" Table)
                let log_pool = pool.clone();
                let log_event = event.clone();
                tokio::spawn(async move {
                    let _ = db::log_event(&log_pool, &log_event).await;
                });

                // 6. TRIGGER ACTIVE MITIGATION
                if is_violating {
                    let isolation_state = Arc::clone(&state);
                    println!("[AEGIS-ENFORCE] Policy breach detected. Engaging reactive isolation.");
                    crate::isolation::trigger_reactive_isolation("hornet-swarm-alpha", &isolation_state).await;
                    
                    // Optional: Push the malicious IP to the eBPF BLOCKLIST map here
                }
            }
        }
    }
}
