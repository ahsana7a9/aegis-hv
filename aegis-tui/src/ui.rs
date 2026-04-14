use ratatui::{prelude::*, widgets::*};
use crate::App; // Import the App struct from main.rs
use aegis_common::Severity;

pub fn ui(f: &mut Frame, app: &App) {
    // 1. Define the Layout
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Min(10),    // Security Event Log
            Constraint::Length(8),  // Entropy Sparkline
        ])
        .split(f.size());

    // 2. Render Header
    let header = Paragraph::new(format!(" 🛡️ AEGIS-HV | Active Agent: {} | Press 'q' to quit, 'k' to Kill", app.current_selected_agent))
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));
    f.render_widget(header, chunks[0]);

    // 3. Render Security Event Table
    let header_cells = ["Timestamp", "Severity", "Reason", "Status"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow)));
    let header_row = Row::new(header_cells).height(1).bottom_margin(1);

    let rows = app.events.iter().rev().map(|ev| {
        let style = match ev.severity {
            Severity::Critical => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            Severity::High => Style::default().fg(Color::LightRed),
            Severity::Medium => Style::default().fg(Color::Yellow),
            Severity::Low => Style::default().fg(Color::Gray),
        };

        Row::new(vec![
            Cell::from(ev.timestamp.format("%H:%M:%S").to_string()),
            Cell::from(format!("{:?}", ev.severity)),
            Cell::from(ev.reason.clone()),
            Cell::from(if ev.mitigated { "🛡️ BLOCKED" } else { "⚠️ ALERT" }),
        ]).style(style)
    });

    let table = Table::new(rows, [
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Min(20),
            Constraint::Length(10),
        ])
        .header(header_row)
        .block(Block::default().borders(Borders::ALL).title(" Live Security Feed "));
    f.render_widget(table, chunks[1]);

    // 4. Render Entropy Sparkline (Visualization of network "noise")
    let sparkline = Sparkline::default()
        .block(Block::default().borders(Borders::ALL).title(" Network Entropy (Exfiltration Risk) "))
        .data(&app.entropy_history)
        .style(Style::default().fg(Color::Magenta));
    f.render_widget(sparkline, chunks[2]);
}
