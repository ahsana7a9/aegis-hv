use sqlx::sqlite::SqlitePool;
use aegis_common::SecurityEvent;
use chrono::Utc;

/// Initializes all database schemas for the Aegis-HV environment.
pub async fn init_db(pool: &SqlitePool) -> anyhow::Result<()> {
    // 1. High-level Security Events (Alerts/Mitigations)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME NOT NULL,
            source TEXT NOT NULL,
            severity TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            reason TEXT NOT NULL,
            mitigated BOOLEAN NOT NULL
        );"
    )
    .execute(pool)
    .await?;

    // 2. Low-level Behavior Forensics (Syscalls/Network/Process)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS behavior_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            pid INTEGER NOT NULL,
            event_type TEXT NOT NULL, 
            details TEXT NOT NULL,    
            risk_score REAL DEFAULT 0.0
        );"
    )
    .execute(pool)
    .await?;

    println!("[DB] Aegis-HV persistence layers initialized.");
    Ok(())
}

/// Logs a high-level security event (e.g., an agent was killed or a policy breached).
pub async fn log_event(pool: &SqlitePool, event: &SecurityEvent) -> anyhow::Result<()> {
    sqlx::query!(
        "INSERT INTO security_logs (timestamp, source, severity, agent_id, reason, mitigated) 
         VALUES (?, ?, ?, ?, ?, ?)",
        event.timestamp,
        format!("{:?}", event.source),
        format!("{:?}", event.severity),
        event.agent_id,
        event.reason,
        event.mitigated
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Logs granular behavior captured from eBPF sensors (The "Black Box" recorder).
pub async fn log_behavior(
    pool: &SqlitePool, 
    pid: u32, 
    event_type: &str, 
    details: &str, 
    risk: f64
) -> anyhow::Result<()> {
    let now = Utc::now();
    sqlx::query!(
        "INSERT INTO behavior_logs (timestamp, pid, event_type, details, risk_score) 
         VALUES (?, ?, ?, ?, ?)",
        now,
        pid,
        event_type,
        details,
        risk
    )
    .execute(pool)
    .await?;
    Ok(())
}
