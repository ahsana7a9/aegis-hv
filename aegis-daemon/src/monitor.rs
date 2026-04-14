use crate::analysis::ThreatAnalyzer;
use crate::policy::PolicyGuard; // Assuming PolicyGuard is in policy.rs
use aegis_common::{SecurityEvent, EventSource, Severity};
use aya::maps::perf::AsyncPerfEventArray;
use aya::maps::MapData;
use tokio::sync::broadcast;
use chrono::Utc;

pub async fn start_shadow_monitoring(
    mut perf_array: AsyncPerfEventArray<MapData>, 
    tx: broadcast::Sender<SecurityEvent>,
    guard: PolicyGuard, // Pass the policy guard into the monitor
) {
    // 16 buffers to match typical CPU core counts or burst handling
    let mut buffers = vec![bytes::BytesMut::with_capacity(1024); 16]; 

    loop {
        // Read events from the Linux kernel
        let events = match perf_array.read_events(&mut buffers).await {
            Ok(e) => e,
            Err(e) => {
                eprintln!("[AEGIS-MONITOR] Error reading perf events: {}", e);
                continue;
            }
        };
        
        for i in 0..events.read {
            let packet_data = &buffers[i];
            
            // 1. RUN ENTROPY ANALYSIS
            let entropy = ThreatAnalyzer::calculate_entropy(packet_data);
            let severity = ThreatAnalyzer::assess_risk(packet_data);

            // 2. CHECK THE POLICY GUARD
            if !guard.is_entropy_safe(entropy) || severity >= Severity::High {
                let mitigated = !guard.is_entropy_safe(entropy);
                
                let event = SecurityEvent {
                    timestamp: Utc::now(),
                    source: EventSource::Shadow,
                    severity: if mitigated { Severity::Critical } else { severity },
                    agent_id: "hornet-swarm-alpha".to_string(), // In production, resolve this via PID
                    action_attempted: "Outbound Network Traffic".to_string(),
                    reason: format!("Entropy: {:.2} (Threshold: {:.2})", 
                             entropy, guard.active_policy.network.max_entropy),
                    mitigated,
                };

                // Broadcast the event to TUI and Web UI
                let _ = tx.send(event);

                // 3. TRIGGER AUTOMATIC MITIGATION
                if mitigated {
                    // This function should be implemented in your isolation.rs or main.rs
                    crate::isolation::trigger_kill("hornet-swarm-alpha").await;
                }
            }
        }
    }
}
