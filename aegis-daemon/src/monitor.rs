use crate::analysis::ThreatAnalyzer;
use aegis_common::{SecurityEvent, EventSource, Severity};
use aya::maps::perf::AsyncPerfEventArray;
use tokio::sync::broadcast;

pub async fn start_shadow_monitoring(
    mut perf_array: AsyncPerfEventArray<aya::maps::MapData>, 
    tx: broadcast::Sender<SecurityEvent>
) {
    let mut buffers = vec![bytes::BytesMut::with_capacity(1024); 16]; 

    loop {
        let events = perf_array.read_events(&mut buffers).await.unwrap();
        
        for i in 0..events.read {
            let packet_data = &buffers[i];
            
            // RUN ENTROPY ANALYSIS
            let severity = ThreatAnalyzer::assess_risk(packet_data);

            if severity >= Severity::High {
                let event = SecurityEvent {
                    timestamp: chrono::Utc::now(),
                    source: EventSource::Shadow,
                    severity,
                    agent_id: "hornet-swarm-alpha".to_string(),
                    action_attempted: "Outbound Network Traffic".to_string(),
                    reason: format!("Suspicious Entropy: {:.2}", ThreatAnalyzer::calculate_entropy(packet_data)),
                    mitigated: false,
                };

                let _ = tx.send(event);
            }
        }
    }
}
