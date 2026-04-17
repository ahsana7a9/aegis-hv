mod analysis;
mod attestation;      //  NEW: Binary integrity verification
mod ipc;
mod secure_ipc;       //  NEW: Secure IPC with peer verification
mod monitor;
mod policy;
mod safe_policy;      //  NEW: Path traversal prevention
mod isolation;
mod db;

use aya::{include_bytes_aligned, Ebpf};
use aya::maps::perf::AsyncPerfEventArray;
use aegis_common::{AegisCommand, SecurityEvent, Severity, EventSource};
use secure_ipc::SecureIpcServer;
use safe_policy::SafePolicyGuard;
use sqlx::sqlite::SqlitePool;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::broadcast;
use attestation::BinaryAttestation;

pub struct AegisState {
    pub fortress_mode_active: AtomicBool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ===== CRITICAL FIX #1: BINARY INTEGRITY VERIFICATION =====
    let expected_hash = std::env::var("AEGIS_BINARY_HASH")
        .map_err(|_| anyhow::anyhow!(
            " FATAL: AEGIS_BINARY_HASH environment variable not set!\n\
             This daemon cannot run without binary integrity verification.\n\
             Set it via: export AEGIS_BINARY_HASH=$(sha256sum target/release/aegis-daemon | cut -d' ' -f1)"
        ))?;

    BinaryAttestation::verify_self(&expected_hash)
        .map_err(|e| anyhow::anyhow!("[FATAL] {}", e))?;

    println!("\x1b[96m");
    println!("--------------------------------------------------");
    println!("     AEGIS-HV: AUTONOMOUS SECURITY KERNEL       ");
    println!("     v1.0.1-Security | Hardened Edition         ");
    println!("--------------------------------------------------");
    println!("\x1b[0m");

    // 1. Initialize State & Persistence
    let state = Arc::new(AegisState {
        fortress_mode_active: AtomicBool::new(true),
    });

    let pool = SqlitePool::connect("sqlite:aegis_audit.db?mode=rwc").await?;
    db::init_db(&pool).await?;

    // ===== CRITICAL FIX #4: SECURE POLICY LOADING =====
    let guard = Arc::new(SafePolicyGuard::load(
        "/etc/aegis/policies",
        "default.yaml",
        None,
    ).map_err(|e| anyhow::anyhow!("[CRITICAL] Policy loading failed: {}", e))?);

    // ===== CRITICAL FIX #2: SECURE IPC INITIALIZATION =====
    let (server, _) = SecureIpcServer::new(Some("/run/aegis"))?;
    let tx = server.tx.clone();

    // 4. Load eBPF Programs (The 'Shadow' Sensors)
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/aegis-ebpf"
    ))?;

    let perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS")
        .map_err(|e| anyhow::anyhow!("Failed to find EVENTS map: {}", e))?)?;

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
            monitor_state,
        )
        .await {
            eprintln!("[AEGIS-DAEMON] Monitor Task Failure: {}", e);
        }
    });

    // 6. Start Secure IPC Server
    println!("[AEGIS-HV] ✓ All security checks passed. Runtime initialized.");
    println!("[AEGIS-HV] ✓ IPC listening on /run/aegis/aegis.sock (root-only)");
    server.start_uds_server().await?;

    Ok(())
}

/// Helper function to route internal security events to the UI and Logs
pub async fn handle_internal_event(event: SecurityEvent) {
    println!("[AEGIS-HV] ALERT: {} - {}", event.agent_id, event.reason);
}

/// Handles incoming commands from external controllers (TUI/Web API)
pub async fn handle_command_ipc(
    cmd: AegisCommand,
    _tx: &broadcast::Sender<SecurityEvent>,
) -> anyhow::Result<()> {
    match cmd {
        AegisCommand::KillAgent { agent_id } => {
            println!(
                "\x1b[91m[AEGIS-HV] MANUAL EMERGENCY KILL: {}\x1b[0m",
                agent_id
            );
            isolation::trigger_kill(&agent_id).await;
        }
        AegisCommand::Ping => { /* Heartbeat check */ }
        _ => println!("[AEGIS-HV] Unknown command received."),
    }
    Ok(())
}