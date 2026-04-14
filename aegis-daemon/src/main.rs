mod analysis;
use analysis::ThreatAnalyzer;
// aegis-daemon/src/monitor.rs

use crate::analysis::ThreatAnalyzer;
use aegis_common::{SecurityEvent, EventSource, Severity};
use aya::maps::perf::AsyncPerfEventArray;
use bytes::BytesMut;
use chrono::Utc;

pub async fn start_shadow_monitoring(mut perf_array: AsyncPerfEventArray<MapData>) {
    // We need a buffer for each CPU core
    let mut buffers = (0..online_cpus().len())
        .map(|_| BytesMut::with_capacity(4096))
        .collect::<Vec<_>>();

    loop {
        // 1. Wait for packets/events from the eBPF kernel program
        let events = perf_array.read_events(&mut buffers).await.unwrap();

        for i in 0..events.read {
            let data = &buffers[i];
            
            // 2. RUN THE ANALYSIS (Your No. 3 code)
            let severity = ThreatAnalyzer::assess_risk(data);

            if severity >= Severity::High {
                let event = SecurityEvent {
                    timestamp: Utc::now(),
                    source: EventSource::Shadow,
                    severity,
                    agent_id: "hornet-01".to_string(),
                    action_attempted: "Outbound Network Packet".to_string(),
                    reason: format!("High entropy: {:.2}", ThreatAnalyzer::calculate_entropy(data)),
                    mitigated: false,
                };

                // 3. BROADCAST TO TUI/WEB
                // This function will send the event through the Unix Socket
                crate::ipc::broadcast_event(event).await;
            }
        }
    }
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load eBPF programs (Shadow Mode)
    let mut bpf = Ebpf::load(include_bytes_aligned!("../../target/bpfel-unknown-none/debug/aegis-ebpf"))?;
    let perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

    // Start the Monitoring Task
    tokio::spawn(async move {
        monitor::start_shadow_monitoring(perf_array).await;
    });

    // Start the IPC Server (TUI/Web Communication)
    ipc::start_uds_server().await?;

    Ok(())
}
mod ipc;
mod analysis;
mod monitor;

use ipc::IpcServer;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Setup the Broadcast Channel
    let (server, _main_rx) = IpcServer::new();
    let tx = server.tx.clone();

    // 2. Start the Shadow Monitor (Passing the Sender)
    tokio::spawn(async move {
        // This task now sends events to the broadcast channel
        monitor::start_shadow_monitoring(tx).await;
    });

    // 3. Start the IPC Server to listen for TUI connections
    server.start_uds_server().await?;

    Ok(())
}
async fn handle_command(cmd: AegisCommand) {
    match cmd {
        AegisCommand::KillAgent { agent_id } => {
            println!("[AEGIS-HV] EMERGENCY KILL issued for agent: {}", agent_id);
            // 1. Look up the agent's control handle (Wasm Atomic or Process PID)
            // 2. Trigger the stop mechanism
            // 3. Broadcast a "Mitigated" event back to the TUI
        },
        _ => { /* Handle other commands */ }
    }
}
