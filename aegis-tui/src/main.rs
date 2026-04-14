use tokio::net::UnixStream;
use tokio::io::AsyncReadExt;
use aegis_common::SecurityEvent;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut stream = UnixStream::connect("/tmp/aegis.sock").await?;
    println!("Connected to Aegis-HV Daemon.");

    loop {
        // Read the length prefix
        let len = stream.read_u32().await? as usize;
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;

        // Deserialize and display
        let event: SecurityEvent = serde_json::from_slice(&buf)?;
        println!("[{}] {:?} - {}", event.timestamp, event.severity, event.reason);
    }
}
