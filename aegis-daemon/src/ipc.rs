use aegis_common::{SecurityEvent, AegisCommand};
use tokio::net::UnixListener;
use tokio::sync::broadcast;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::fs;

pub struct IpcServer {
    pub tx: broadcast::Sender<SecurityEvent>,
}

impl IpcServer {
    pub fn new() -> (Self, broadcast::Receiver<SecurityEvent>) {
        let (tx, rx) = broadcast::channel(1024);
        (Self { tx }, rx)
    }

    pub async fn start_uds_server(self) -> anyhow::Result<()> {
        let socket_path = "/tmp/aegis.sock";

        if fs::metadata(socket_path).is_ok() {
            fs::remove_file(socket_path)?;
        }

        let listener = UnixListener::bind(socket_path)?;
        println!("[AEGIS-HV] IPC Server listening on {}", socket_path);

        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    let mut rx = self.tx.subscribe();
                    let tx_for_handler = self.tx.clone(); // If needed for internal feedback

                    tokio::spawn(async move {
                        loop {
                            tokio::select! {
                                // Outbound: Security Events -> TUI/Web
                                Ok(event) = rx.recv() => {
                                    let json = serde_json::to_vec(&event).unwrap();
                                    if stream.write_u32(json.len() as u32).await.is_err() { break; }
                                    if stream.write_all(&json).await.is_err() { break; }
                                }
                                // Inbound: Commands -> Daemon
                                result = stream.read_u32() => {
                                    match result {
                                        Ok(len) => {
                                            let mut cmd_buf = vec![0u8; len as usize];
                                            if stream.read_exact(&mut cmd_buf).await.is_ok() {
                                                if let Ok(cmd) = serde_json::from_slice::<AegisCommand>(&cmd_buf) {
                                                    // This function should be implemented in main.rs or a logic module
                                                    crate::handle_command(cmd).await; 
                                                }
                                            }
                                        }
                                        Err(_) => break, // Connection closed
                                    }
                                }
                            }
                        }
                    });
                }
                Err(e) => eprintln!("[AEGIS-HV] IPC Accept Error: {}", e),
            }
        }
    }
}
