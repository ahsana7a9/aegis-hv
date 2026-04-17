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
pub struct SecureIpcServer {
    pub tx: broadcast::Sender<SecurityEvent>,
    socket_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct PeerCredentials {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

impl SecureIpcServer {
    pub fn new(socket_dir: Option<&str>) -> anyhow::Result<(Self, broadcast::Receiver<SecurityEvent>)> {
        let socket_dir = socket_dir.unwrap_or("/run/aegis");
        let socket_dir_path = Path::new(socket_dir);

        let metadata = fs::metadata(socket_dir_path)
            .map_err(|e| anyhow!(
                "Socket directory {:?} not found or not accessible: {}",
                socket_dir_path, e
            ))?;

        #[cfg(unix)]
        {
            let perms = metadata.permissions().mode();
            if (perms & 0o077) != 0 {
                return Err(anyhow!(
                    " SECURITY ERROR: Socket directory has insecure permissions: {:o}\n\
                     Must be 0700 or 0750 for security (root-only or root+group)\n\
                     Fix: sudo chmod 0700 {}",
                    perms, socket_dir
                ));
            }
        }

        let socket_path = socket_dir_path.join("aegis.sock");

        if socket_path.exists() {
            fs::remove_file(&socket_path)
                .map_err(|e| anyhow!("Failed to remove old socket: {}", e))?;
        }

        let (tx, rx) = broadcast::channel(1024);

        Ok((Self { tx, socket_path }, rx))
    }

    fn verify_peer_credentials(fd: i32) -> anyhow::Result<PeerCredentials> {
        use nix::sys::socket::UnixCredentials;

        let cred: UnixCredentials = getsockopt(fd, sockopt::SO_PEERCRED)
            .map_err(|e| anyhow!("Failed to get peer credentials: {}", e))?;

        let peer = PeerCredentials {
            uid: cred.uid(),
            gid: cred.gid(),
            pid: cred.pid(),
        };

        if peer.uid != 0 {
            return Err(anyhow!(
                " SECURITY ALERT: Connection attempt from non-root peer (UID {})\n\
                 Only root (UID 0) can control the daemon",
                peer.uid
            ));
        }

        Ok(peer)
    }

    pub async fn start_uds_server(self) -> anyhow::Result<()> {
        let listener = UnixListener::bind(&self.socket_path)?;

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
                            eprintln!("[AEGIS-IPC]   {}", e);
                        }
                    }
                }
                Err(e) => eprintln!("[AEGIS-IPC] Accept error: {}", e),
            }
        }
    }

    async fn handle_verified_peer(
        mut stream: tokio::net::UnixStream,
        mut rx: broadcast::Receiver<SecurityEvent>,
        tx: broadcast::Sender<SecurityEvent>,
    ) -> anyhow::Result<()> {
        const MAX_MESSAGE_SIZE: u32 = 65536;

        loop {
            tokio::select! {
                Ok(event) = rx.recv() => {
                    match serde_json::to_vec(&event) {
                        Ok(json) => {
                            if let Err(e) = stream.write_u32(json.len() as u32).await {
                                eprintln!("[AEGIS-IPC] Failed to write event length: {}", e);
                                break;
                            }
                            if let Err(e) = stream.write_all(&json).await {
                                eprintln!("[AEGIS-IPC] Failed to write event data: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            eprintln!("[AEGIS-IPC] Serialization error (skipping event): {}", e);
                            continue;
                        }
                    }
                }

                result = stream.read_u32() => {
                    match result {
                        Ok(len) => {
                            if len > MAX_MESSAGE_SIZE {
                                eprintln!(
                                    "[AEGIS-IPC]  Message too large: {} bytes (max: {})",
                                    len, MAX_MESSAGE_SIZE
                                );
                                break;
                            }

                            let mut cmd_buf = vec![0u8; len as usize];
                            match stream.read_exact(&mut cmd_buf).await {
                                Ok(_) => {
                                    match serde_json::from_slice::<AegisCommand>(&cmd_buf) {
                                        Ok(cmd) => {
                                            println!("[AEGIS-IPC] Received command: {:?}", cmd);
                                            if let Err(e) = crate::handle_command_ipc(cmd, &tx).await {
                                                eprintln!("[AEGIS-IPC] Command handling error: {}", e);
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("[AEGIS-IPC] Deserialization error: {}", e);
                                            continue;
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!("[AEGIS-IPC] Read error: {}", e);
                                    break;
                                }
                            }
                        }
                        Err(_) => break,
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
        // Tests would go here
    }
}
