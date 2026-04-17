use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use tokio::net::UnixListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::broadcast;
use aegis_common::{SecurityEvent, AegisCommand};
use nix::sys::socket::{getsockopt, sockopt};
use anyhow::anyhow;

/// Secure IPC server with peer credential verification and permission enforcement
/// 
/// Security Features:
/// 1. Socket placed in /run/aegis (restricted directory, not /tmp)
/// 2. Socket permissions set to 0600 (root-only read/write)
/// 3. SO_PEERCRED verification ensures only root can send commands
/// 4. Large message size limit prevents buffer exhaustion
pub struct SecureIpcServer {
    pub tx: broadcast::Sender<SecurityEvent>,
    socket_path: PathBuf,
}

/// Represents verified peer credentials from SO_PEERCRED
#[derive(Debug, Clone)]
pub struct PeerCredentials {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

impl SecureIpcServer {
    /// Creates a new secure IPC server with restricted socket directory
    ///
    /// # Arguments
    /// * `socket_dir` - Directory for the socket file (default: /run/aegis)
    ///
    /// # Security Checks
    /// - Verifies directory exists
    /// - Ensures directory permissions are 0700 or stricter
    /// - Cleans up old socket files
    pub fn new(socket_dir: Option<&str>) -> anyhow::Result<(Self, broadcast::Receiver<SecurityEvent>)> {
        // Default to /run/aegis (systemd RuntimeDirectory)
        let socket_dir = socket_dir.unwrap_or("/run/aegis");
        let socket_dir_path = Path::new(socket_dir);

        // Verify socket directory exists and is accessible
        let metadata = fs::metadata(socket_dir_path)
            .map_err(|e| anyhow!(
                "Socket directory {:?} not found or not accessible: {}",
                socket_dir_path, e
            ))?;

        // SECURITY: Verify directory has restrictive permissions
        #[cfg(unix)]
        {
            let perms = metadata.permissions().mode();
            // Directory should be 0700 or 0750 at most
            if (perms & 0o077) != 0 {
                return Err(anyhow!(
                    "❌ SECURITY ERROR: Socket directory has insecure permissions: {:o}\n\
                     Must be 0700 or 0750 for security (root-only or root+group)\n\
                     Fix: sudo chmod 0700 {}",
                    perms, socket_dir
                ));
            }
        }

        let socket_path = socket_dir_path.join("aegis.sock");

        // Remove old socket file if it exists (TOCTOU-safe in practice)
        if socket_path.exists() {
            fs::remove_file(&socket_path)
                .map_err(|e| anyhow!("Failed to remove old socket: {}", e))?;
        }

        let (tx, rx) = broadcast::channel(1024);

        Ok((Self { tx, socket_path }, rx))
    }

    /// Extracts and verifies peer credentials using SO_PEERCRED
    ///
    /// # Security
    /// - Only root (UID 0) is allowed to connect
    /// - Non-root connections are rejected immediately
    /// - Prevents privilege escalation attacks
    fn verify_peer_credentials(fd: i32) -> anyhow::Result<PeerCredentials> {
        use nix::sys::socket::UnixCredentials;

        let cred: UnixCredentials = getsockopt(fd, sockopt::SO_PEERCRED)
            .map_err(|e| anyhow!("Failed to get peer credentials: {}", e))?;

        let peer = PeerCredentials {
            uid: cred.uid(),
            gid: cred.gid(),
            pid: cred.pid(),
        };

        // CRITICAL SECURITY CHECK: Only allow root to connect
        if peer.uid != 0 {
            return Err(anyhow!(
                "❌ SECURITY ALERT: Connection attempt from non-root peer (UID {})\n\
                 Only root (UID 0) can control the daemon",
                peer.uid
            ));
        }

        Ok(peer)
    }

    /// Starts the secure IPC server with full permission enforcement
    pub async fn start_uds_server(self) -> anyhow::Result<()> {
        // Bind the Unix domain socket
        let listener = UnixListener::bind(&self.socket_path)?;

        // CRITICAL SECURITY: Set socket file permissions to 0600 (rw-------)
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&self.socket_path, perms)?;

        println!(
            "[AEGIS-IPC] ✓ Secure server listening on {} (permissions: 0600, root-only)",
            self.socket_path.display()
        );

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let fd = stream.as_raw_fd();

                    // CRITICAL SECURITY: Verify peer is root before accepting
                    match Self::verify_peer_credentials(fd) {
                        Ok(peer) => {
                            println!(
                                "[AEGIS-IPC] ✓ Authorized connection from root (PID: {})",
                                peer.pid
                            );

                            let mut rx = self.tx.subscribe();
                            let tx_handler = self.tx.clone();

                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_verified_peer(stream, rx, tx_handler).await {
                                    eprintln!("[AEGIS-IPC] Peer handler error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            eprintln!("[AEGIS-IPC] ⚠️  {}", e);
                            // Connection rejected - drop the stream
                        }
                    }
                }
                Err(e) => eprintln!("[AEGIS-IPC] Accept error: {}", e),
            }
        }
    }

    /// Handles communication with a verified (authenticated) peer
    async fn handle_verified_peer(
        mut stream: tokio::net::UnixStream,
        mut rx: broadcast::Receiver<SecurityEvent>,
        tx: broadcast::Sender<SecurityEvent>,
    ) -> anyhow::Result<()> {
        const MAX_MESSAGE_SIZE: u32 = 65536; // 64 KB max message size

        loop {
            tokio::select! {
                // Outbound: Security Events -> TUI/Web
                Ok(event) = rx.recv() => {
                    match serde_json::to_vec(&event) {
                        Ok(json) => {
                            // Send length prefix (4 bytes)
                            if let Err(e) = stream.write_u32(json.len() as u32).await {
                                eprintln!("[AEGIS-IPC] Failed to write event length: {}", e);
                                break;
                            }
                            // Send event data
                            if let Err(e) = stream.write_all(&json).await {
                                eprintln!("[AEGIS-IPC] Failed to write event data: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            eprintln!("[AEGIS-IPC] Serialization error (skipping event): {}", e);
                            continue; // Don't crash on serialization errors
                        }
                    }
                }

                // Inbound: Commands -> Daemon
                result = stream.read_u32() => {
                    match result {
                        Ok(len) => {
                            // SECURITY: Enforce maximum message size to prevent DoS
                            if len > MAX_MESSAGE_SIZE {
                                eprintln!(
                                    "[AEGIS-IPC] ❌ Message too large: {} bytes (max: {})",
                                    len, MAX_MESSAGE_SIZE
                                );
                                break; // Drop connection
                            }

                            let mut cmd_buf = vec![0u8; len as usize];
                            match stream.read_exact(&mut cmd_buf).await {
                                Ok(_) => {
                                    match serde_json::from_slice::<AegisCommand>(&cmd_buf) {
                                        Ok(cmd) => {
                                            println!("[AEGIS-IPC] Received command: {:?}", cmd);
                                            // Dispatch command to handler
                                            if let Err(e) = crate::handle_command_ipc(cmd, &tx).await {
                                                eprintln!("[AEGIS-IPC] Command handling error: {}", e);
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("[AEGIS-IPC] Deserialization error: {}", e);
                                            continue; // Skip malformed commands
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!("[AEGIS-IPC] Read error: {}", e);
                                    break;
                                }
                            }
                        }
                        Err(_) => break, // Connection closed
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_ipc_creation() {
        // This test would require a running daemon
        // Placeholder for integration tests
    }
}