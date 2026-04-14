⁷use aegis_common::SecurityEvent;
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::sync::broadcast;
use tokio::io::AsyncWriteExt;
use std::fs;

pub struct IpcServer {
    pub tx: broadcast::Sender<SecurityEvent>,
}

impl IpcServer {
    pub fn new() -> (Self, broadcast::Receiver<SecurityEvent>) {
        let (tx, rx) = broadcast::channel(1024); // Buffer up to 1024 events
        (Self { tx }, rx)
    }

    pub async fn start_uds_server(self) -> anyhow::Result<()> {
        let socket_path = "/tmp/aegis.sock";

        // Clean up stale socket from previous runs
        if fs::metadata(socket_path).is_ok() {
            fs::remove_file(socket_path)?;
        }

        let listener = UnixListener::bind(socket_path)?;
        println!("[AEGIS-HV] IPC Server listening on {}", socket_path);

        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    let mut rx = self.tx.subscribe();
                    
                    // Spawn a task to handle each connected client (TUI or Web)
                    tokio::spawn(async move {
                        while let Ok(event) = rx.recv().await {
                            let json = serde_json::to_vec(&event).unwrap();
                            // Frame the data: [length: u32][payload]
                            if stream.write_u32(json.len() as u32).await.is_err() { break; }
                            if stream.write_all(&json).await.is_err() { break; }
                        }
                    });
                }
                Err(e) => eprintln!("[AEGIS-HV] IPC Error: {}", e),
            }
        }
    }
}
use tokio::io::AsyncReadExt;
use crate::AegisCommand; // Import the new enum

// Inside your tokio::spawn loop in start_uds_server:
tokio::spawn(async move {
    let mut rx = tx_clone.subscribe();
    let mut buf = [0u8; 1024];

    loop {
        tokio::select! {
            // Outbound: Send Security Events to TUI
            Ok(event) = rx.recv() => {
                let json = serde_json::to_vec(&event).unwrap();
                if stream.write_u32(json.len() as u32).await.is_err() { break; }
                if stream.write_all(&json).await.is_err() { break; }
            }
            // Inbound: Listen for Commands from TUI
            result = stream.read_u32() => {
                if let Ok(len) = result {
                    let mut cmd_buf = vec![0u8; len as usize];
                    if stream.read_exact(&mut cmd_buf).await.is_ok() {
                        if let Ok(cmd) = serde_json::from_slice::<AegisCommand>(&cmd_buf) {
                            handle_command(cmd).await; // The logic to actually kill the agent
                        }
                    }
                } else { break; }
            }
        }
    }
});

