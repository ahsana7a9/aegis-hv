//! Centralized error definitions for Aegis-HV
//!
//! All error messages are defined here for:
//! - Easy maintenance
//! - Consistency across codebase
//! - Future internationalization
//! - User-friendly error reporting
//!

use std::fmt;

/// Aegis-HV Error Types
#[derive(Debug, Clone)]
pub enum AegisError {
    /// Binary integrity verification failed
    BinaryIntegrityMismatch {
        expected: String,
        computed: String,
    },

    /// Binary file has insecure permissions
    BinaryInsecurePermissions {
        path: String,
        mode: String,
    },

    /// IPC socket configuration error
    IpcSocketError {
        reason: String,
    },

    /// IPC peer authentication failed (non-root)
    IpcPeerUnauthorized {
        uid: u32,
    },

    /// Policy file not found or inaccessible
    PolicyLoadFailed {
        path: String,
        reason: String,
    },

    /// Policy file path traversal attack detected
    PolicyPathTraversalDetected {
        attempted_path: String,
        base_directory: String,
    },

    /// Policy file has insecure permissions
    PolicyInsecurePermissions {
        path: String,
        mode: String,
    },

    /// Policy file integrity verification failed
    PolicyIntegrityMismatch {
        expected_hash: String,
        computed_hash: String,
    },

    /// Process termination failed
    ProcessTerminationFailed {
        pid: u32,
        reason: String,
    },

    /// Process verification via waitpid() failed
    ProcessVerificationFailed {
        pid: u32,
    },

    /// Mitigation already in progress
    MitigationInProgress,

    /// Isolation already active for agent
    IsolationAlreadyActive {
        agent_id: String,
    },

    /// Database operation failed
    DatabaseError {
        operation: String,
        reason: String,
    },

    /// Configuration error
    ConfigurationError {
        key: String,
        reason: String,
    },

    /// Generic runtime error
    RuntimeError {
        reason: String,
    },
}

impl fmt::Display for AegisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AegisError::BinaryIntegrityMismatch {
                expected,
                computed,
            } => {
                write!(
                    f,
                    "🔴 BINARY INTEGRITY VERIFICATION FAILED!\n\
                     \n\
                     Expected Hash: {}\n\
                     Computed Hash: {}\n\
                     \n\
                     The daemon binary has been modified or is unauthorized.\n\
                     This is a critical security issue. Refusing to start.\n\
                     \n\
                     Possible causes:\n\
                     - Unauthorized modification by attacker\n\
                     - Corrupted installation\n\
                     - Man-in-the-middle attack\n\
                     \n\
                     Actions:\n\
                     1. Verify binary source (git log, build artifacts)\n\
                     2. Reinstall from trusted source\n\
                     3. Review system logs for unauthorized access\n\
                     4. Consider security audit",
                    expected, computed
                )
            }

            AegisError::BinaryInsecurePermissions { path, mode } => {
                write!(
                    f,
                    "🔴 BINARY FILE HAS INSECURE PERMISSIONS!\n\
                     \n\
                     Path: {}\n\
                     Current Mode: {}\n\
                     \n\
                     The daemon binary is writable by non-root users.\n\
                     This allows privilege escalation attacks.\n\
                     \n\
                     Fix:\n\
                     sudo chmod 0755 {}\n\
                     sudo chown root:root {}\n\
                     \n\
                     Then restart: sudo systemctl restart aegis-hv.service",
                    path, mode, path, path
                )
            }

            AegisError::IpcSocketError { reason } => {
                write!(
                    f,
                    "🔴 IPC SOCKET ERROR!\n\
                     \n\
                     Reason: {}\n\
                     \n\
                     The daemon cannot create its control socket at /run/aegis/aegis.sock\n\
                     \n\
                     Troubleshooting:\n\
                     1. Check /run/aegis directory exists: ls -la /run/aegis/\n\
                     2. Verify permissions (should be 0700): stat /run/aegis/\n\
                     3. Fix permissions: sudo chmod 0700 /run/aegis/\n\
                     4. Check disk space: df -h /run/\n\
                     5. Check logs: sudo journalctl -u aegis-hv.service -n 20",
                    reason
                )
            }

            AegisError::IpcPeerUnauthorized { uid } => {
                write!(
                    f,
                    "🔴 SECURITY ALERT: UNAUTHORIZED IPC CONNECTION!\n\
                     \n\
                     Peer User ID: {} (expected 0 for root)\n\
                     \n\
                     A non-root process attempted to connect to the daemon control socket.\n\
                     Only root (UID 0) is allowed to send commands to the daemon.\n\
                     \n\
                     This connection has been rejected.\n\
                     \n\
                     If this was intentional:\n\
                     1. Run your command as root: sudo <your-command>\n\
                     2. Or add your user to the aegis group (not recommended)",
                    uid
                )
            }

            AegisError::PolicyLoadFailed { path, reason } => {
                write!(
                    f,
                    "🔴 FAILED TO LOAD SECURITY POLICY!\n\
                     \n\
                     Path: {}\n\
                     Reason: {}\n\
                     \n\
                     The daemon cannot start without a valid security policy.\n\
                     \n\
                     Troubleshooting:\n\
                     1. Check file exists: ls -la {}\n\
                     2. Check readability: sudo cat {}\n\
                     3. Validate YAML: yamllint {}\n\
                     4. Verify permissions (should be 0640): stat {}\n\
                     5. Fix: sudo chmod 0640 {}\n\
                     6. Check parent dir (should be 0750): stat /etc/aegis/policies/",
                    path, reason, path, path, path, path, path
                )
            }

            AegisError::PolicyPathTraversalDetected {
                attempted_path,
                base_directory,
            } => {
                write!(
                    f,
                    "🔴 SECURITY ERROR: POLICY PATH TRAVERSAL DETECTED!\n\
                     \n\
                     Attempted Path: {}\n\
                     Base Directory: {}\n\
                     \n\
                     This is either:\n\
                     1. A symlink attack: Policy file is a symlink to /etc/passwd\n\
                     2. A directory traversal: Filename contains ../ or absolute path\n\
                     \n\
                     The daemon has rejected this configuration for security reasons.\n\
                     \n\
                     To fix:\n\
                     1. Verify policy files are not symlinks:\n\
                        ls -L /etc/aegis/policies/\n\
                     2. Remove symlinks and copy files:\n\
                        sudo cp /path/to/policy.yaml /etc/aegis/policies/\n\
                        sudo rm -f /etc/aegis/policies/evil-link.yaml\n\
                     3. Verify canonical path:\n\
                        sudo realpath /etc/aegis/policies/default.yaml",
                    attempted_path, base_directory
                )
            }

            AegisError::PolicyInsecurePermissions { path, mode } => {
                write!(
                    f,
                    "🔴 SECURITY ERROR: POLICY FILE HAS INSECURE PERMISSIONS!\n\
                     \n\
                     Path: {}\n\
                     Current Mode: {} (world-writable or world-readable)\n\
                     Expected Mode: 0640\n\
                     \n\
                     Any user on the system could modify the security policy,\n\
                     defeating all protections.\n\
                     \n\
                     Fix immediately:\n\
                     sudo chmod 0640 {}\n\
                     sudo chown root:root {}\n\
                     \n\
                     Then restart:\n\
                     sudo systemctl restart aegis-hv.service",
                    path, mode, path, path
                )
            }

            AegisError::PolicyIntegrityMismatch {
                expected_hash,
                computed_hash,
            } => {
                write!(
                    f,
                    "🔴 SECURITY ERROR: POLICY FILE INTEGRITY CHECK FAILED!\n\
                     \n\
                     Expected Hash: {}\n\
                     Computed Hash: {}\n\
                     \n\
                     The policy file has been modified since deployment.\n\
                     This could indicate:\n\
                     1. Unauthorized modification\n\
                     2. File corruption\n\
                     3. Accidental edit\n\
                     \n\
                     Actions:\n\
                     1. Review recent changes: sudo git log /etc/aegis/policies/\n\
                     2. Restore from backup: sudo cp /backup/default.yaml /etc/aegis/policies/\n\
                     3. Verify new hash matches expected\n\
                     4. Restart daemon: sudo systemctl restart aegis-hv.service",
                    expected_hash, computed_hash
                )
            }

            AegisError::ProcessTerminationFailed { pid, reason } => {
                write!(
                    f,
                    "🔴 FAILED TO TERMINATE PROCESS!\n\
                     \n\
                     PID: {}\n\
                     Reason: {}\n\
                     \n\
                     The daemon could not send SIGKILL to the rogue process.\n\
                     This indicates:\n\
                     1. Process already dead\n\
                     2. Not running as root\n\
                     3. Process in uninterruptible sleep (kernel issue)\n\
                     \n\
                     Diagnostics:\n\
                     - Check process: ps -p {} -o state,comm\n\
                     - Check state: cat /proc/{}/status | grep State\n\
                     - Force kill: sudo kill -9 {}\n\
                     - Check kernel: dmesg | tail -20",
                    pid, reason, pid, pid, pid
                )
            }

            AegisError::ProcessVerificationFailed { pid } => {
                write!(
                    f,
                    "🔴 CRITICAL: PROCESS TERMINATION VERIFICATION FAILED!\n\
                     \n\
                     PID: {}\n\
                     \n\
                     The process refused to die even after SIGKILL.\n\
                     This is extremely rare and indicates:\n\
                     1. Kernel bug\n\
                     2. Hardware fault\n\
                     3. Process in uninterruptible state (D state)\n\
                     \n\
                     Emergency Actions:\n\
                     1. Check kernel panic: dmesg | grep -i panic\n\
                     2. Check I/O state: ps -p {} -o state,comm\n\
                     3. Check hanging filesystem: df -i\n\
                     4. Consider system reboot\n\
                     5. File bug report with kernel version",
                    pid, pid
                )
            }

            AegisError::MitigationInProgress => {
                write!(
                    f,
                    "⚠️  MITIGATION ALREADY IN PROGRESS!\n\
                     \n\
                     The daemon is currently executing a mitigation action.\n\
                     A second concurrent request has been rejected to prevent\n\
                     race conditions.\n\
                     \n\
                     This is a security feature, not an error.\n\
                     Please wait for the current mitigation to complete.\n\
                     \n\
                     Monitoring:\n\
                     - Check status: sudo systemctl status aegis-hv.service\n\
                     - View logs: sudo journalctl -u aegis-hv.service -f\n\
                     - Wait time: typically < 5 seconds"
                )
            }

            AegisError::IsolationAlreadyActive { agent_id } => {
                write!(
                    f,
                    "⚠️  ISOLATION ALREADY IN PROGRESS FOR THIS AGENT!\n\
                     \n\
                     Agent ID: {}\n\
                     \n\
                     A previous isolation command is still executing.\n\
                     Duplicate request has been rejected.\n\
                     \n\
                     Please wait for the ongoing isolation to complete.",
                    agent_id
                )
            }

            AegisError::DatabaseError { operation, reason } => {
                write!(
                    f,
                    "🔴 DATABASE ERROR!\n\
                     \n\
                     Operation: {}\n\
                     Reason: {}\n\
                     \n\
                     Failed to access the audit database.\n\
                     \n\
                     Troubleshooting:\n\
                     1. Check database file: ls -la /var/lib/aegis/aegis_audit.db\n\
                     2. Check permissions: stat /var/lib/aegis/\n\
                     3. Check disk space: df -h /var/lib/aegis/\n\
                     4. Check SQLite: sudo sqlite3 /var/lib/aegis/aegis_audit.db '.tables'\n\
                     5. Check logs: sudo journalctl -u aegis-hv.service -n 50",
                    operation, reason
                )
            }

            AegisError::ConfigurationError { key, reason } => {
                write!(
                    f,
                    "🔴 CONFIGURATION ERROR!\n\
                     \n\
                     Key: {}\n\
                     Reason: {}\n\
                     \n\
                     The daemon configuration is invalid.\n\
                     \n\
                     Troubleshooting:\n\
                     1. Check environment variables: env | grep AEGIS\n\
                     2. Check systemd config: cat /etc/systemd/system/aegis-hv.service\n\
                     3. Verify paths exist:\n\
                        - /etc/aegis/policies/\n\
                        - /var/lib/aegis/\n\
                        - /var/log/aegis/\n\
                     4. Check permissions: stat /etc/aegis/",
                    key, reason
                )
            }

            AegisError::RuntimeError { reason } => {
                write!(
                    f,
                    "🔴 RUNTIME ERROR!\n\
                     \n\
                     Reason: {}\n\
                     \n\
                     An unexpected error occurred.\n\
                     \n\
                     Diagnostics:\n\
                     1. Check logs: sudo journalctl -u aegis-hv.service -n 50\n\
                     2. Check system: dmesg | tail -20\n\
                     3. Check disk: df -h /\n\
                     4. Check memory: free -h\n\
                     5. Check processes: ps aux | grep aegis",
                    reason
                )
            }
        }
    }
}

impl std::error::Error for AegisError {}

/// Convenience type alias for Results
pub type AegisResult<T> = Result<T, AegisError>;

// ═════════════════════════════════════════════════════════════════════════════
// HELPER CONSTRUCTORS
// ═════════════════════════════════════════════════════════════════════════════

impl AegisError {
    pub fn binary_integrity(expected: &str, computed: &str) -> Self {
        AegisError::BinaryIntegrityMismatch {
            expected: expected.to_string(),
            computed: computed.to_string(),
        }
    }

    pub fn binary_permissions(path: &str, mode: u32) -> Self {
        AegisError::BinaryInsecurePermissions {
            path: path.to_string(),
            mode: format!("{:o}", mode),
        }
    }

    pub fn ipc_socket(reason: &str) -> Self {
        AegisError::IpcSocketError {
            reason: reason.to_string(),
        }
    }

    pub fn policy_load_failed(path: &str, reason: &str) -> Self {
        AegisError::PolicyLoadFailed {
            path: path.to_string(),
            reason: reason.to_string(),
        }
    }

    pub fn policy_path_traversal(attempted: &str, base: &str) -> Self {
        AegisError::PolicyPathTraversalDetected {
            attempted_path: attempted.to_string(),
            base_directory: base.to_string(),
        }
    }

    pub fn process_termination_failed(pid: u32, reason: &str) -> Self {
        AegisError::ProcessTerminationFailed {
            pid,
            reason: reason.to_string(),
        }
    }

    pub fn database_error(operation: &str, reason: &str) -> Self {
        AegisError::DatabaseError {
            operation: operation.to_string(),
            reason: reason.to_string(),
        }
    }
}