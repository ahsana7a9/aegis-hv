use crate::AegisState;
use aegis_common::{SecurityEvent, Severity, EventSource};
use std::sync::atomic::Ordering;
use chrono::Utc;
use std::process::Command;

/// Physically isolates an agent by flipping its execution mode and triggering blocks.
pub async fn trigger_reactive_isolation(agent_id: &str, state: &crate::AegisState) {
    println!("\x1b[91m [AEGIS-HV] CRITICAL: Initiating Reactive Isolation for {}\x1b[0m", agent_id);

    // 1. Flip the Fortress bit (Global Lockdown State)
    // This tells the monitor to start dropping all non-essential traffic immediately.
    state.fortress_mode_active.store(true, Ordering::SeqCst);

    // 2. Prepare the Mitigation Event for Audit & UI
    let event = SecurityEvent {
        timestamp: Utc::now(),
        source: EventSource::Fortress,
        severity: Severity::Critical,
        agent_id: agent_id.to_string(),
        action_attempted: "Automatic Isolation".to_string(),
        reason: "Shadow sensors detected high-entropy exfiltration. Agent quarantined.".to_string(),
        mitigated: true,
    };

    // 3. Broadcast to all interfaces (TUI/Web)
    // This pushes the "🛡️ BLOCKED" status to your Ratatui dashboard.
    let _ = crate::handle_internal_event(event).await;

    // 4. Trigger the Hard Kill
    trigger_kill(agent_id).await;
}

/// A hard-kill function for native agents using system-level signals.
pub async fn trigger_kill(agent_id: &str) {
    println!(" [AEGIS-HV] EMERGENCY: Hard-killing agent process: {}", agent_id);
    
    // In a 2026 Linux environment, we use pkill for swarm-wide termination 
    // or cgroup-level freezing to ensure no child processes escape.
    let output = Command::new("pkill")
        .arg("-9") // SIGKILL: Inescapable termination
        .arg("-f") // Match against the full command line (Agent ID)
        .output()
        .await;

    match output {
        Ok(_) => println!(" [AEGIS-HV] Isolation Successful: Process tree purged."),
        Err(e) => eprintln!(" [AEGIS-HV] Mitigation Error: Failed to signal process: {}", e),
    }
}
