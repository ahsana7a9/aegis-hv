mod analysis;
mod ipc;
mod monitor;
mod policy;
mod isolation; // Placeholder for your kill logic

use aya::{include_bytes_aligned, Ebpf};
use aya::maps::perf::AsyncPerfEventArray;
use aegis_common::{AegisCommand, SecurityEvent, Severity, EventSource};
use ipc::IpcServer;
use policy::PolicyGuard;
use std::sync::Arc;
use chrono::Utc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!(" AEGIS-HV DAEMON STARTING...");

    // 1. Load Security Policy
    let guard = PolicyGuard::load("policies/default.yaml")
        .expect("Failed to load mandatory security policy");

    // 2. Initialize IPC (Broadcast Channel for TUI/Web)
    let (server, _main_rx) = IpcServer::new();
    let tx = server.tx.clone();

    // 3. Load eBPF Programs (Shadow Mode Sensors)
    // Ensure the path matches your xtask build output
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/aegis-ebpf"
    ))?;
    
    let perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

    // 4. Spawn Shadow Monitor Task
    // Pass the sender and the policy guard into the monitor
    tokio::spawn(async move {
        if let Err(e) = monitor::start_shadow_monitoring(perf_array, tx, guard).await {
            eprintln!("[AEGIS-DAEMON] Monitor Task Failed: {}", e);
        }
    });

    // 5. Start IPC Server (This blocks the main thread and keeps the daemon alive)
    server.start_uds_server().await?;

    Ok(())
}

/// Handles incoming commands from the TUI or Web UI
pub async fn handle_command(cmd: AegisCommand) {
    match cmd {
        AegisCommand::KillAgent { agent_id } => {
            println!("[AEGIS-HV] EMERGENCY KILL issued for agent: {}", agent_id);
            // Logic to interface with isolation.rs or Wasmtime handles
            // crate::isolation::kill_agent(&agent_id).await;
        },
        AegisCommand::Ping => {
            println!("[AEGIS-HV] IPC Heartbeat received.");
        },
        _ => println!("[AEGIS-HV] Received unhandled command: {:?}", cmd),
    }
}
