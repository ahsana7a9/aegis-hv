// crates/aegis-ipc/src/server.rs

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tokio::net::{UnixListener, UnixStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::broadcast;
use aegis_common::{SecurityEvent, AegisCommand};
use anyhow::anyhow;

pub struct IpcServer {
    pub tx: broadcast::Sender<SecurityEvent>,
    socket_path: PathBuf,
}

impl IpcServer {
    pub fn new(socket_dir: Option<&str>) -> anyhow::Result<(Self, broadcast::Receiver<SecurityEvent>)> {
        let socket_dir = socket_dir.unwrap_or("/run/aegis");
        let socket_path = Path::new(socket_dir).join("aegis.sock");

        if socket_path.exists() {
            fs::remove_file(&socket_path)?;
        }

        let (tx, rx) = broadcast::channel(1024);

        Ok((Self { tx, socket_path }, rx))
    }

    pub async fn start(self) -> anyhow::Result<()> {
        let listener = UnixListener::bind(&self.socket_path)?;

        fs::set_permissions(&self.socket_path, fs::Permissions::from_mode(0o600))?;

        loop {
            let (stream, _) = listener.accept().await?;
            let tx = self.tx.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, tx).await {
                    eprintln!("[IPC] Connection error: {}", e);
                }
            });
        }
    }
}

async fn handle_connection(
    mut stream: UnixStream,
    tx: broadcast::Sender<SecurityEvent>,
) -> anyhow::Result<()> {
    const MAX_MESSAGE_SIZE: u32 = 65536;

    loop {
        let len = match stream.read_u32().await {
            Ok(l) => l,
            Err(_) => break,
        };

        if len > MAX_MESSAGE_SIZE {
            return Err(anyhow!("Message too large"));
        }

        let mut buf = vec![0; len as usize];
        stream.read_exact(&mut buf).await?;

        let cmd: AegisCommand = serde_json::from_slice(&buf)?;

        // 🔴 Forward to supervisor instead of handling locally
        crate::client::send_to_supervisor(cmd).await?;
    }

    Ok(())
}