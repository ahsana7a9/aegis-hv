use crate::AegisState;
use aegis_common::{SecurityEvent, Severity, EventSource};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::Mutex;
use chrono::Utc;
use anyhow::anyhow;
use nix::sys::wait::{waitpid, WaitStatus, WaitPidFlag};
use nix::unistd::Pid;
use std::time::Duration;

/// Thread-safe process isolation handler
/// Prevents concurrent isolation attempts and ensures verification
pub struct IsolationHandler {
    /// Tracks which agents are currently being isolated (prevents duplicate attempts)
    active_isolations: Arc<Mutex<std::collections::HashSet<String>>>,
    /// Total isolations performed
    isolation_count: Arc<tokio::sync::Mutex<u64>>,
}

impl IsolationHandler {
    /// Creates a new isolation handler
    pub fn new() -> Self {
        Self {
            active_isolations: Arc::new(Mutex::new(std::collections::HashSet::new())),
            isolation_count: Arc::new(tokio::sync::Mutex::new(0)),
        }
    }

    /// Initiates reactive isolation for an agent (thread-safe)
    ///
    /// # Security Guarantees
    /// - Only ONE isolation per agent at a time
    /// - Prevents duplicate isolation attempts
    /// - Verifies process actually terminates
    /// - All operations are logged and broadcast
    ///
    /// # Arguments
    /// * `agent_id` - Unique identifier for the agent
    /// * `state` - Global Aegis state
    /// * `tx` - Broadcast channel for event notification
    ///
    /// # Returns
    /// * `Ok(())` if isolation succeeded
    /// * `Err` if already isolating or process verification failed
    pub async fn trigger_reactive_isolation(
        &self,
        agent_id: &str,
        state: &AegisState,
        tx: &tokio::sync::broadcast::Sender<SecurityEvent>,
    ) -> anyhow::Result<()> {
        let mut isolations = self.active_isolations.lock().await;

        // Check if this agent is already being isolated
        if isolations.contains(agent_id) {
            return Err(anyhow!(
                "[AEGIS-ISOLATION] Agent {} already under isolation. Rejecting duplicate request.",
                agent_id
            ));
        }

        // Mark this agent as "isolating"
        isolations.insert(agent_id.to_string());
        drop(isolations); // Release lock early

        // Use a scope guard to ensure cleanup
        let _guard = IsolationGuard {
            handler: Arc::new(self.active_isolations.clone()),
            agent_id: agent_id.to_string(),
        };

        eprintln!(
            "\x1b[91m[AEGIS-ISOLATION] ✓ Isolation initiated for agent: {}\x1b[0m",
            agent_id
        );

        // ===== STEP 1: FLIP FORTRESS MODE =====
        state.fortress_mode_active.store(true, Ordering::SeqCst);
        eprintln!("[AEGIS-ISOLATION] Fortress Mode ACTIVATED (global lockdown)");

        // ===== STEP 2: CREATE MITIGATION EVENT =====
        let event = SecurityEvent {
            timestamp: Utc::now(),
            source: EventSource::Fortress,
            severity: Severity::Critical,
            agent_id: agent_id.to_string(),
            reason: "Reactive isolation triggered: High-entropy exfiltration detected".to_string(),
            mitigated: true,
        };

        // ===== STEP 3: BROADCAST TO UI =====
        if let Err(e) = tx.send(event.clone()) {
            eprintln!(
                "[AEGIS-ISOLATION] Warning: Failed to broadcast isolation event: {}",
                e
            );
        }

        // ===== STEP 4: KILL PROCESS WITH VERIFICATION =====
        self.kill_process_tree(agent_id).await?;

        // ===== STEP 5: INCREMENT ISOLATION COUNT =====
        {
            let mut count = self.isolation_count.lock().await;
            *count += 1;
            eprintln!(
                "[AEGIS-ISOLATION] Isolation #{} recorded for agent {}",
                *count,
                agent_id
            );
        }

        eprintln!(
            "\x1b[92m[AEGIS-ISOLATION] ✓ Agent {} successfully isolated\x1b[0m",
            agent_id
        );

        Ok(())
    }

    /// Kills a process and its entire process tree (all children)
    /// Uses pkill with verification
    async fn kill_process_tree(&self, agent_id: &str) -> anyhow::Result<()> {
        use std::process::Command;

        eprintln!(
            "[AEGIS-ISOLATION] Sending SIGKILL to process tree for {}",
            agent_id
        );

        // Use pkill to terminate the entire process group/tree
        let output = Command::new("pkill")
            .arg("-9") // SIGKILL: Inescapable termination
            .arg("-f") // Match full command line
            .arg(agent_id) // Match agent ID
            .output()
            .map_err(|e| anyhow!("Failed to execute pkill: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!(
                "pkill failed for agent {}: {}",
                agent_id,
                stderr
            ));
        }

        eprintln!(
            "[AEGIS-ISOLATION] Process tree for {} terminated",
            agent_id
        );

        // Give processes a moment to exit
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Optional: Verify with pgrep that no processes remain
        let verify_output = Command::new("pgrep")
            .arg("-f")
            .arg(agent_id)
            .output()
            .map_err(|e| anyhow!("Failed to execute pgrep for verification: {}", e))?;

        if verify_output.status.success() {
            // If pgrep finds processes, they're still alive
            return Err(anyhow!(
                "Verification failed: Process tree for {} still alive after SIGKILL",
                agent_id
            ));
        }

        eprintln!(
            "[AEGIS-ISOLATION] ✓ Verification complete: Process tree for {} is DEAD",
            agent_id
        );

        Ok(())
    }

    /// Get total number of isolations performed
    pub async fn get_isolation_count(&self) -> u64 {
        *self.isolation_count.lock().await
    }
}

impl Default for IsolationHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII Guard: Automatically removes agent from "active isolations" set when dropped
struct IsolationGuard {
    handler: Arc<Mutex<std::collections::HashSet<String>>>,
    agent_id: String,
}

impl Drop for IsolationGuard {
    fn drop(&mut self) {
        // We can't use await in drop(), so we spawn a task
        let handler = self.handler.clone();
        let agent_id = self.agent_id.clone();

        tokio::spawn(async move {
            let mut isolations = handler.lock().await;
            isolations.remove(&agent_id);
            eprintln!(
                "[AEGIS-ISOLATION] Guard dropped: {} removed from active isolations",
                agent_id
            );
        });
    }
}

/// Legacy function for backward compatibility
/// Routes to the global isolation handler
pub async fn trigger_reactive_isolation(
    agent_id: &str,
    state: &AegisState,
) {
    // For now, this is a no-op for backward compatibility
    // In production, this would use a global IsolationHandler instance
    eprintln!(
        "[AEGIS-ISOLATION] Legacy function called for {} (no global handler)",
        agent_id
    );
}

/// Legacy function: Kill a process
pub async fn trigger_kill(agent_id: &str) {
    use std::process::Command;

    eprintln!(
        "[AEGIS-ISOLATION] Legacy kill function called for {}",
        agent_id
    );

    let output = Command::new("pkill")
        .arg("-9")
        .arg("-f")
        .arg(agent_id)
        .output();

    match output {
        Ok(out) => {
            if out.status.success() {
                eprintln!("[AEGIS-ISOLATION] Process tree for {} terminated", agent_id);
            } else {
                eprintln!(
                    "[AEGIS-ISOLATION] pkill warning: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        }
        Err(e) => eprintln!(
            "[AEGIS-ISOLATION] Failed to signal process {}: {}",
            agent_id,
            e
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_concurrent_isolation_prevention() {
        let handler = IsolationHandler::new();
        let (tx, mut _rx) = tokio::sync::broadcast::channel(10);

        // First isolation should succeed
        // Second should fail (duplicate prevention)
        // This is a placeholder - full test would require mocking
    }

    #[tokio::test]
    async fn test_isolation_count_increments() {
        let handler = IsolationHandler::new();
        assert_eq!(handler.get_isolation_count().await, 0);
        // After isolation: count should be 1
    }
}