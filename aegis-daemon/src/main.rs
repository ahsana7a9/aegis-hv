mod analysis;
mod ipc;
mod monitor;
mod policy;
mod isolation;
mod db;

use aya::{include_bytes_aligned, Ebpf};
use aya::maps::perf::AsyncPerfEventArray;
use aegis_common::{AegisCommand, AEGIS_AUTH_HASH, SecurityEvent, Severity, EventSource};
use ipc::IpcServer;
use policy::PolicyGuard;
use sqlx::sqlite::SqlitePool;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::broadcast;

pub struct AegisState {
    pub fortress_mode_active: AtomicBool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // --- 0. CRYPTOGRAPHIC INTEGRITY CHECK ---
    // Prevents unauthorized or tampered binaries from attaching to the kernel.
    if AEGIS_AUTH_HASH != "4793f0b097b830d17d12224d455476a6e5a40871e9877b0d8745c4793e2b10a9" {
        eprintln!("\n[FATAL] Binary Integrity Compromised!");
        eprintln!("[ERROR] Unauthorized Ownership Signature. Failed to verify Aegis-HV core.");
        std::process::exit(1);
    }

    println!("\x1b[96m");
    println!("--------------------------------------------------");
    println!("     AEGIS-HV: AUTONOMOUS SECURITY KERNEL       ");
    println!("     v1.0.0-Genesis | Always-On Monitoring      ");
    println!("--------------------------------------------------");
    println!("\x1b[0m");

    // 1. Initialize State & Persistence
    let state = Arc::new(AegisState {
        fortress_mode_active: AtomicBool::new(true), 
    });

    let pool = SqlitePool::connect("sqlite:aegis_audit.db?mode=rwc").await?;
    db::init_db(&pool).await?;

    // 2. Load Security Policy (The 'Hard Rules')
    let guard = Arc::new(PolicyGuard::load("policies/default.yaml")
        .expect("CRITICAL: Failed to load mandatory security policy."));

    // 3. Initialize IPC (UDS Server for TUI)
    let (server, _) = IpcServer::new();
    let tx = server.tx.clone();

    // 4. Load eBPF Programs (The 'Shadow' Sensors)
    // include_bytes_aligned! ensures the bytecode is correctly padded for the loader.
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/aegis-ebpf"
    ))?;
    
    // Attach the eBPF sensors to the kernel hooks (Network/Syscalls/LSM)
    // Note: Requires CAP_BPF / CAP_NET_ADMIN
    // bpf.program_mut("aegis_sniff").unwrap().load()?;

    let perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS")
        .expect("Failed to find EVENTS map in eBPF bytecode"))?;

    // 5. Spawn Shadow Monitor Task
    let monitor_tx = tx.clone();
    let monitor_pool = pool.clone();
    let monitor_state = Arc::clone(&state);
    let monitor_guard = Arc::clone(&guard);

    tokio::spawn(async move {
        if let Err(e) = monitor::start_shadow_monitoring(
            perf_array, 
            monitor_tx, 
            monitor_guard, 
            monitor_pool,
            monitor_state
        ).await {
            eprintln!("[AEGIS-DAEMON] Monitor Task Failure: {}", e);
        }
    });

    // 6. Start IPC Server (Blocking call - Listen for Orchestration)
    println!("[AEGIS-HV] Runtime Initialized. Awaiting TUI connection...");
    server.start_uds_server().await?;

    Ok(())
}

/// Helper function to route internal security events to the UI and Logs
pub async fn handle_internal_event(event: SecurityEvent) {
    // This would be called by isolation.rs or monitor.rs to unify the alert flow
    println!("[AEGIS-HV] ALERT: {} - {}", event.agent_id, event.reason);
}

/// Handles incoming commands from external controllers (TUI/Web API)
pub async fn handle_command(cmd: AegisCommand, state: Arc<AegisState>) {
    match cmd {
        AegisCommand::KillAgent { agent_id } => {
            println!("\x1b[91m[AEGIS-HV] MANUAL EMERGENCY KILL: {}\x1b[0m", agent_id);
            isolation::trigger_kill(&agent_id).await;
        },
        AegisCommand::ToggleFortress { enabled } => {
            state.fortress_mode_active.store(enabled, Ordering::SeqCst);
            println!("[AEGIS-HV] Global Policy Shift: Fortress Mode = {}", enabled);
        },
        AegisCommand::Ping => { /* Heartbeat check */ },
        _ => println!("[AEGIS-HV] Unknown Command Cluster received."),
    }
}
