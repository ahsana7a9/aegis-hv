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
use std::sync::atomic::{AtomicBool, Ordering};

pub struct AegisState {
    pub fortress_mode_active: AtomicBool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // --- 0. CRYPTOGRAPHIC OWNERSHIP CHECK ---
    // Strict enforcement of the signature hash before any kernel hooks are attached.
    if AEGIS_AUTH_HASH != "4793f0b097b830d17d12224d455476a6e5a40871e9877b0d8745c4793e2b10a9" {
        eprintln!("\n[FATAL] Binary Integrity Compromised!");
        eprintln!("[ERROR] Unauthorized Ownership Signature. Failed to verify Aegis-HV core.");
        std::process::exit(1);
    }

    println!("--------------------------------------------------");
    println!("     AEGIS-HV: AUTONOMOUS SECURITY KERNEL       ");
    println!("--------------------------------------------------");

    // 1. Initialize State & Persistence
    let state = Arc::new(AegisState {
        fortress_mode_active: AtomicBool::new(true), // Default to active protection
    });

    let pool = SqlitePool::connect("sqlite:aegis_audit.db?mode=rwc").await?;
    db::init_db(&pool).await?;
    println!("[AEGIS-HV] Audit database initialized (SQLite).");

    // 2. Load Security Policy (Deterministic Rules)
    let guard = Arc::new(PolicyGuard::load("policies/default.yaml")
        .expect("CRITICAL: Failed to load mandatory security policy. System cannot start."));
    println!("[AEGIS-HV] Security policy loaded: [Mode: {}]", guard.active_policy.role);

    // 3. Initialize IPC (UDS Server)
    let (server, _) = IpcServer::new();
    let tx = server.tx.clone();

    // 4. Load eBPF Programs (Shadow Mode Sensors)
    // Loading with aya; requires root/CAP_BPF
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/aegis-ebpf"
    ))?;
    
    // Extract the ring buffer for kernel->userspace telemetry
    let perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS")
        .expect("Failed to find EVENTS map in eBPF bytecode"))?;

    // 5. Spawn Shadow Monitor Task
    // This task handles the bridge between eBPF signals and the Policy Engine.
    let monitor_tx = tx.clone();
    let monitor_pool = pool.clone();
    let monitor_state = Arc::clone(&state);
    let monitor_guard = Arc::clone(&guard); // Pass the policy guard to the monitor

    tokio::spawn(async move {
        println!("[AEGIS-HV] Shadow Monitoring active (eBPF Sensors Linked).");
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

    // 6. Start IPC Server (Blocking call)
    println!("[AEGIS-HV] Listening on UDS for TUI/Web Orchestration...");
    server.start_uds_server().await?;

    Ok(())
}

/// Handles incoming commands from external controllers (TUI/Web API)
pub async fn handle_command(cmd: AegisCommand, state: Arc<AegisState>) {
    match cmd {
        AegisCommand::KillAgent { agent_id } => {
            println!("[AEGIS-HV]  EMERGENCY KILL issued for agent: {}", agent_id);
            isolation::trigger_kill(&agent_id).await;
        },
        AegisCommand::ToggleFortress { enabled } => {
            state.fortress_mode_active.store(enabled, Ordering::SeqCst);
            println!("[AEGIS-HV] Policy Shift: Fortress Mode set to {}", enabled);
        },
        AegisCommand::Ping => {
            // Heartbeat for IPC health checks
        },
        _ => println!("[AEGIS-HV] Received unknown or unhandled command: {:?}", cmd),
    }
}
