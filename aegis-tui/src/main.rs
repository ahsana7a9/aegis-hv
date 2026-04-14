use ratatui::{prelude::*, widgets::*};
use crossterm::event::{self, Event, KeyCode};
use tokio::net::UnixStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use aegis_common::{SecurityEvent, AegisCommand};
use std::time::Duration;

struct App {
    events: Vec<SecurityEvent>,
    current_selected_agent: String,
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
    let mut app = App { 
        events: Vec::new(),
        current_selected_agent: "hornet-swarm-alpha".to_string(),
    };

    // 3. Main Loop
    loop {
        terminal.draw(|f| ui(f, &app))?;

        // A. Handle User Input
        if event::poll(Duration::from_millis(10))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('k') => {
                        let cmd = AegisCommand::KillAgent { 
                            agent_id: app.current_selected_agent.clone() 
                        };
                        let json = serde_json::to_vec(&cmd)?;
                        stream.write_u32(json.len() as u32).await?;
                        stream.write_all(&json).await?;
                    }
                    _ => {}
                }
            }
        }

        // B. Handle Inbound Data (Non-blocking check)
        let mut len_buf = [0u8; 4];
        // try_read only succeeds if there are at least 4 bytes waiting
        if let Ok(4) = stream.try_read(&mut len_buf) {
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut buf = vec![0u8; len];
            if stream.read_exact(&mut buf).await.is_ok() {
                if let Ok(ev) = serde_json::from_slice::<SecurityEvent>(&buf) {
                    app.events.push(ev);
                    if app.events.len() > 30 { app.events.remove(0); }
                }
            }
        }
        
        tokio::task::yield_now().await; // Ensure the executor has time for the socket
    }

    // 4. Cleanup
    crossterm::terminal::disable_raw_mode()?;
    crossterm::execute!(terminal.backend_mut(), crossterm::terminal::LeaveAlternateScreen)?;
    Ok(())
}

// Placeholder for the UI function we defined earlier
fn ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(f.size());

    let header = Paragraph::new("🛡️ AEGIS-HV MONITOR")
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(header, chunks[0]);

    let list_items: Vec<ListItem> = app.events.iter().map(|ev| {
        let color = match ev.severity {
            aegis_common::Severity::Critical => Color::Red,
            aegis_common::Severity::High => Color::LightRed,
            _ => Color::Gray,
        };
        ListItem::new(format!("[{:?}] {} - {}", ev.severity, ev.agent_id, ev.reason))
            .style(Style::default().fg(color))
    }).collect();

    let list = List::new(list_items)
        .block(Block::default().borders(Borders::ALL).title("Live Threats"));
    f.render_widget(list, chunks[1]);
}
