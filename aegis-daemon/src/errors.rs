/// Centralized error messages for Aegis-HV
/// All error strings are defined here for easy maintenance and internationalization

use std::fmt;

/// Security-related errors
#[derive(Debug, Clone)]
pub enum AegisError {
    BinaryIntegrity { expected: String, got: String },
    BinaryPermissions { actual_mode: String },
    IpcSocket { reason: String },
    IpcPeerAuth { uid: u32 },
    PolicyLoad { path: String, reason: String },
    PolicyPathTraversal { attempted: String, base: String },
    PolicyFilePermissions { path: String, mode: String },
    PolicyIntegrityMismatch { expected: String, got: String },
    MitigationInProgress,
    ProcessTerminationFailed { pid: u32, reason: String },
    ProcessVerificationFailed { pid: u32 },
    IsolationAlreadyActive { agent_id: String },
}

impl fmt::Display for AegisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AegisError::BinaryIntegrity { expected, got } => {
                write!(
                    f,
                    "🔴 BINARY INTEGRITY VERIFICATION FAILED!\n\
                     Expected: {}\n\
                     Got:      {}\n\
                     This daemon binary has been modified or is unauthorized.\n\
                     Refusing to start.",
                    expected,
                    got
                )
            }
            AegisError::BinaryPermissions { actual_mode } => {
                write!(
                    f,
                    "🔴 BINARY FILE HAS INSECURE PERMISSIONS!\n\
                     Mode: {} (world-writable)\n\
                     Fix: sudo chmod 0755 /usr/local/bin/aegis-daemon\n\
                     Refusing to start.",
                    actual_mode
                )
            }
            AegisError::IpcSocket { reason } => {
                write!(
                    f,
                    "🔴 IPC SOCKET ERROR!\n\
                     Reason: {}\n\
                     Check: /run/aegis permissions (should be 0700)\n\
                     Setup: sudo mkdir -p /run/aegis && sudo chmod 0700 /run/aegis",
                    reason
                )
            }
            AegisError::IpcPeerAuth { uid } => {
                write!(
                    f,
                    "🔴 SECURITY ALERT: IPC CONNECTION FROM UNAUTHORIZED USER!\n\
                     Peer UID: {} (only UID 0/root allowed)\n\
                     Connection rejected.",
                    uid
                )
            }
            AegisError::PolicyLoad { path, reason } => {
                write!(
                    f,
                    "🔴 FAILED TO LOAD POLICY FILE!\n\
                     Path: {}\n\
                     Reason: {}\n\
                     Check: File exists and has correct permissions (0640)\n\
                     Setup: sudo cp policies/default.yaml /etc/aegis/policies/",
                    path,
                    reason
                )
            }
            AegisError::PolicyPathTraversal { attempted, base } => {
                write!(
                    f,
                    "🔴 SECURITY ERROR: POLICY PATH TRAVERSAL DETECTED!\n\
                     Attempted path: {}\n\
                     Base directory: {}\n\
                     This is likely a symlink attack or directory traversal.\n\
                     Fix: Verify policy files are directly in {} and not symlinked.",
                    attempted,
                    base,
                    base
                )
            }
            AegisError::PolicyFilePermissions { path, mode } => {
                write!(
                    f,
                    "🔴 SECURITY ERROR: POLICY FILE HAS INSECURE PERMISSIONS!\n\
                     Path: {}\n\
                     Mode: {} (world-writable or world-readable)\n\
                     Fix: sudo chmod 0640 {}",
                    path,
                    mode,
                    path
                )
            }
            AegisError::PolicyIntegrityMismatch { expected, got } => {
                write!(
                    f,
                    "🔴 SECURITY ERROR: POLICY FILE INTEGRITY CHECK FAILED!\n\
                     Expected hash: {}\n\
                     Got hash:      {}\n\
                     The policy file has been modified or tampered with.\n\
                     Action: Restore from trusted backup or recreate policy.",
                    expected,
                    got
                )
            }
            AegisError::MitigationInProgress => {
                write!(
                    f,
                    "⚠️  MITIGATION ALREADY IN PROGRESS!\n\
                     A previous mitigation is still executing.\n\
                     Action: Wait for current mitigation to complete."
                )
            }
            AegisError::ProcessTerminationFailed { pid, reason } => {
                write!(
                    f,
                    "🔴 FAILED TO TERMINATE PROCESS!\n\
                     PID: {}\n\
                     Reason: {}\n\
                     Potential causes:\n\
                     - Process already dead\n\
                     - Permission denied (not running as root)\n\
                     - Process in uninterruptible sleep state (D state)",
                    pid,
                    reason
                )
            }
            AegisError::ProcessVerificationFailed { pid } => {
                write!(
                    f,
                    "🔴 CRITICAL: PROCESS TERMINATION VERIFICATION FAILED!\n\
                     PID: {}\n\
                     The process refused to die after SIGKILL.\n\
                     This indicates:\n\
                     - Kernel bug or hardware issue\n\
                     - Process in uninterruptible state\n\
                     - System reboot may be required\n\
                     Action: Check kernel logs: dmesg | tail -50",
                    pid
                )
            }
            AegisError::IsolationAlreadyActive { agent_id } => {
                write!(
                    f,
                    "⚠️  ISOLATION ALREADY IN PROGRESS FOR THIS AGENT!\n\
                     Agent ID: {}\n\
                     Rejecting duplicate isolation request.",
                    agent_id
                )
            }
        }
    }
}

impl std::error::Error for AegisError {}

/// Helper functions for error creation
impl AegisError {
    pub fn binary_integrity(expected: &str, got: &str) -> Self {
        AegisError::BinaryIntegrity {
            expected: expected.to_string(),
            got: got.to_string(),
        }
    }

    pub fn binary_permissions(mode: u32) -> Self {
        AegisError::BinaryPermissions {
            actual_mode: format!("{:o}", mode),
        }
    }

    pub fn ipc_socket(reason: &str) -> Self {
        AegisError::IpcSocket {
            reason: reason.to_string(),
        }
    }

    pub fn policy_path_traversal(attempted: &str, base: &str) -> Self {
        AegisError::PolicyPathTraversal {
            attempted: attempted.to_string(),
            base: base.to_string(),
        }
    }

    pub fn process_termination_failed(pid: u32, reason: &str) -> Self {
        AegisError::ProcessTerminationFailed {
            pid,
            reason: reason.to_string(),
        }
    }
}

/// Convenience type alias
pub type AegisResult<T> = Result<T, AegisError>;