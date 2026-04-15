use ratatui::{prelude::*, widgets::*};
use crate::App; 
use aegis_common::Severity;

pub fn ui(f: &mut Frame, app: &App) {
    // 1. Define the Layout with a sidebar for Agent Metadata
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Min(30),    // Main Feed
            Constraint::Length(35), // Agent Metadata Sidebar
        ])
        .split(f.size());

    let left_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Min(10),    // Security Event Table
            Constraint::Length(8),  // Entropy Sparkline
        ])
        .split(main_chunks[0]);

    // 2. Render Header (Breadcrumbs & Status)
    let header = Paragraph::new(format!(
        "   AEGIS-HV | Active Swarm: {} | [q] Quit [k] Kill [f] Toggle Fortress", 
        app.current_selected_agent
    ))
    .block(Block::default().borders(Borders::ALL))
    .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));
    f.render_widget(header, left_chunks[0]);

    // 3. Render Security Event Table (Forensic Feed)
    let header_cells = ["TIME", "SEVERITY", "INCIDENT REASON", "DEFENSE"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)));
    let header_row = Row::new(header_cells).height(1).bottom_margin(0);

    let rows = app.events.iter().rev().take(20).map(|ev| {
        let (color, icon) = match ev.severity {
            Severity::Critical => (Color::Red, "✘"),
            Severity::High => (Color::LightRed, "▲"),
            Severity::Medium => (Color::Yellow, "◆"),
            Severity::Low => (Color::Blue, "●"),
        };

        Row::new(vec![
            Cell::from(ev.timestamp.format("%H:%M:%S").to_string()),
            Cell::from(format!("{} {:?}", icon, ev.severity)),
            Cell::from(ev.reason.clone()),
            Cell::from(if ev.mitigated { "  ISOLATED" } else { "👁️  LOGGED" }),
        ]).style(Style::default().fg(color))
    });

    let table = Table::new(rows, [
            Constraint::Length(10),
            Constraint::Length(12),
            Constraint::Min(30),
            Constraint::Length(12),
        ])
        .header(header_row)
        .block(Block::default()
            .borders(Borders::ALL)
            .title(" LIVE KERNEL AUDIT TRAIL ")
            .title_alignment(Alignment::Center));
    f.render_widget(table, left_chunks[1]);

    // 4. Render Entropy Sparkline (Real-time Detection visualization)
    let sparkline = Sparkline::default()
        .block(Block::default()
            .borders(Borders::ALL)
            .title(" NETWORK ENTROPY (AI EXFILTRATION RISK) "))
        .data(&app.entropy_history)
        .style(Style::default().fg(Color::Magenta));
    f.render_widget(sparkline, left_chunks[2]);

    // 5. Sidebar: Agent Forensics
    let sidebar = Paragraph::new(vec![
        Line::from(vec![Span::raw("Agent: "), Span::styled(&app.current_selected_agent, Style::default().fg(Color::Green))]),
        Line::from(format!("Uptime: {}s", app.uptime)),
        Line::from(format!("Baseline Entropy: {:.2}", app.baseline_entropy)),
        Line::from("-".repeat(30)),
        Line::from("DECENTRALIZED INTELLIGENCE:"),
        Line::from("Hornet-Swarm-Alpha v1.0.0"),
    ])
    .block(Block::default().borders(Borders::ALL).title(" AGENT CONTEXT "));
    f.render_widget(sidebar, main_chunks[1]);
}
