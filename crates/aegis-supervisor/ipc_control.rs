// crates/aegis-supervisor/src/ipc_control.rs

use std::os::unix::io::AsRawFd;
use tokio::net::UnixListener;
use tokio::io::{AsyncReadExt};
use nix::sys::socket::{getsockopt, sockopt};
use aegis_common::AegisCommand;
use anyhow::anyhow;

pub struct SupervisorIpc;

impl SupervisorIpc {
    pub async fn start(socket_path: &str) -> anyhow::Result<()> {
        let listener = UnixListener::bind(socket_path)?;

        loop {
            let (stream, _) = listener.accept().await?;
            let fd = stream.as_raw_fd();

            match verify_peer(fd) {
                Ok(_) => {
                    tokio::spawn(async move {
                        if let Err(e) = handle_root_command(stream).await {
                            eprintln!("[SUPERVISOR] Command error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("[SUPERVISOR] Unauthorized: {}", e);
                }
            }
        }
    }
}

fn verify_peer(fd: i32) -> anyhow::Result<()> {
    use nix::sys::socket::UnixCredentials;

    let cred: UnixCredentials = getsockopt(fd, sockopt::SO_PEERCRED)?;

    if cred.uid() != 0 {
        return Err(anyhow!("Non-root access denied"));
    }

    Ok(())
}

async fn handle_root_command(
    mut stream: tokio::net::UnixStream,
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

        // 🔴 REAL privileged execution
        execute_command(cmd).await?;
    }

    Ok(())
}

async fn execute_command(cmd: AegisCommand) -> anyhow::Result<()> {
    match cmd {
        AegisCommand::KillProcess(pid) => {
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid as i32),
                nix::sys::signal::SIGKILL,
            )?;
        }

        AegisCommand::BlockIP(ip) => {
            // update eBPF map
        }

        _ => {}
    }

    Ok(())
}
