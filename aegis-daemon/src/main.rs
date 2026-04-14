mod analysis;
mod ipc;
mod monitor;
mod policy;
mod isolation;
mod db;

use aya::{include_bytes_aligned, Ebpf};
use aya::maps::perf::AsyncPerfEventArray;
use aegis_common::{AegisCommand, AEGIS_AUTH_HASH};
use ipc::IpcServer;
use policy::PolicyGuard;
use sqlx::sqlite::SqlitePool;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

pub struct AegisState {
    pub fortress_mode_active: AtomicBool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // --- 0. CRYPTOGRAPHIC OWNERSHIP CHECK ---
    // If the hash in common/lib.rs doesn't match the author's signature, exit.
    if AEGIS_AUTH_HASH != "4793f0b097b830d17d12224d455476a6e5a40871e9877b0d8745c4793e2b10a9" {
        eprintln!("[FATAL] Binary Integrity Compromised: Unauthorized Ownership Signature.");
        std::process::exit(1);
    }

    println!(" AEGIS-HV DAEMON STARTING...");

    // 1. Initialize State & Database
    let state = Arc::new(AegisState {
        fortress_mode_active: AtomicBool::new(false),
    });

    let pool = SqlitePool::connect("sqlite:aegis_audit.db?mode=rwc").await?;
    db::init_db(&pool).await?;
    println!("[AEGIS-HV] Audit database initialized.");

    // 2. Load Security Policy
    let guard = PolicyGuard::load("policies/default.yaml")
        .expect("Failed to load mandatory security policy");

    // 3. Initialize IPC (Broadcast Channel)
    let (server, _) = IpcServer::new();
    let tx = server.tx.clone();

    // 4. Load eBPF Programs (Shadow Mode Sensors)
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/aegis-ebpf"
    ))?;
    
    // Connect to the perf ring buffer in the kernel
    let perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

    // 5. Spawn Shadow Monitor Task
    let monitor_tx = tx.clone();
    let monitor_pool = pool.clone();
    let monitor_state = Arc::clone(&state);

    tokio::spawn(async move {
        if let Err(e) = monitor::start_shadow_monitoring(
            perf_array, 
            monitor_tx, 
            guard, 
            monitor_pool,
            monitor_state
        ).await {
            eprintln!("[AEGIS-DAEMON] Monitor Task Failed: {}", e);
        }
    });

    // 6. Start IPC Server (Blocks)
    println!("[AEGIS-HV] IPC server listening for TUI/Web connections...");
    server.start_uds_server().await?;

    Ok(())
}

/// Handles incoming commands from the TUI or Web UI
pub async fn handle_command(cmd: AegisCommand) {
    match cmd {
        AegisCommand::KillAgent { agent_id } => {
            println!("[AEGIS-HV] EMERGENCY KILL issued for agent: {}", agent_id);
            isolation::trigger_kill(&agent_id).await;
        },
        AegisCommand::Ping => {
            println!("[AEGIS-HV] Heartbeat: IPC check valid.");
        },
        _ => println!("[AEGIS-HV] Received unhandled command: {:?}", cmd),
    }
}
