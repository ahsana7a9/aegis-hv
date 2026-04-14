mod ui; // Assuming the ui logic is in ui.rs

use ratatui::{prelude::*, widgets::*};
use crossterm::event::{self, Event, KeyCode};
use tokio::net::UnixStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use aegis_common::{SecurityEvent, AegisCommand};
use std::time::Duration;

pub struct App {
    pub events: Vec<SecurityEvent>,
    pub current_selected_agent: String,
    pub entropy_history: Vec<u64>, 
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
    // Fallback error message if the daemon isn't running
    let mut stream = UnixStream::connect("/tmp/aegis.sock").await
        .map_err(|_| "Could not connect to Aegis-HV Daemon. Is it running?")?;

    let mut app = App { 
        events: Vec::new(),
        current_selected_agent: "hornet-swarm-alpha".to_string(),
        entropy_history: Vec::new(),
    };

    // 3. Main Loop
    loop {
        // Draw the UI (defined in ui.rs)
        terminal.draw(|f| ui::ui(f, &app))?;

        // A. Handle User Input (Keyboard)
        if event::poll(Duration::from_millis(10))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('k') => {
                        let cmd = AegisCommand::KillAgent { 
                            agent_id: app.current_selected_agent.clone() 
                        };
                        let json = serde_json::to_vec(&cmd)?;
                        // Send command with length prefix
                        stream.write_u32(json.len() as u32).await?;
                        stream.write_all(&json).await?;
                    }
                    _ => {}
                }
            }
        }

        // B. Handle Inbound Security Events
        let mut len_buf = [0u8; 4];
        if let Ok(4) = stream.try_read(&mut len_buf) {
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut buf = vec![0u8; len];
            if stream.read_exact(&mut buf).await.is_ok() {
                if let Ok(ev) = serde_json::from_slice::<SecurityEvent>(&buf) {
                    // Update state
                    app.events.push(ev);
                    if app.events.len() > 30 { app.events.remove(0); }
                    
                    // Logic to extract entropy for the chart could go here
                }
            }
        }
        
        // C. Yield to let async background tasks process
        tokio::task::yield_now().await;
    }

    // 4. Cleanup Terminal
    crossterm::terminal::disable_raw_mode()?;
    crossterm::execute!(
        terminal.backend_mut(),
        crossterm::terminal::LeaveAlternateScreen
    )?;
    
    Ok(())
}
