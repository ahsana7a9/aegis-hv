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
// Inside your TUI event loop (using Ratatui/Crossterm)
if let Event::Key(key) = event::read()? {
    if key.code == KeyCode::Char('k') {
        let cmd = AegisCommand::KillAgent { 
            agent_id: current_selected_agent.clone() 
        };
        let json = serde_json::to_vec(&cmd)?;
        
        // Write to the Unix Socket
        stream.write_u32(json.len() as u32).await?;
        stream.write_all(&json).await?;
    }
}

use ratatui::{prelude::*, widgets::*};
use crossterm::event::{self, Event, KeyCode};
use tokio::net::UnixStream;
use tokio::io::AsyncReadExt;
use aegis_common::SecurityEvent;

struct App {
    events: Vec<SecurityEvent>,
    entropy_history: Vec<u64>, // For the chart
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Terminal Setup
    crossterm::terminal::enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // 2. Connect to Daemon
    let mut stream = UnixStream::connect("/tmp/aegis.sock").await?;
    let mut app = App { events: Vec::new(), entropy_history: Vec::new() };

    // 3. Main Loop
    loop {
        terminal.draw(|f| ui(f, &app))?;

        // Check for User Input
        if event::poll(std::time::Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') { break; }
                if key.code == KeyCode::Char('k') { 
                    // Send "Kill" command back to daemon (logic from previous step)
                }
            }
        }

        // 4. Non-blocking read from Daemon
        let mut len_buf = [0u8; 4];
        if stream.try_read(&mut len_buf).is_ok() {
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await?;
            let ev: SecurityEvent = serde_json::from_slice(&buf)?;
            
            // Update app state
            app.events.push(ev);
            if app.events.len() > 20 { app.events.remove(0); }
        }
    }

    // Cleanup
    crossterm::terminal::disable_raw_mode()?;
    Ok(())
}
