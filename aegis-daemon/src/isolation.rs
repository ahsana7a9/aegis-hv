use crate::AegisState;
use aegis_common::{SecurityEvent, Severity, EventSource};
use std::sync::atomic::Ordering;

pub async fn trigger_reactive_isolation(agent_id: &str, state: &AegisState) {
    println!("[AEGIS-HV] CRITICAL: Initiating Reactive Isolation for {}", agent_id);

    // 1. Flip the Fortress bit for this agent
    state.fortress_mode_active.store(true, Ordering::SeqCst);

    // 2. Broadcast the mitigation event to TUI and Web
    let event = SecurityEvent {
        timestamp: chrono::Utc::now(),
        source: EventSource::System,
        severity: Severity::Critical,
        agent_id: agent_id.to_string(),
        action_attempted: "Automatic Isolation".to_string(),
        reason: "Shadow sensors detected a high-entropy data leak.".to_string(),
        mitigated: true,
    };

    crate::ipc::broadcast_event(event).await;
}
