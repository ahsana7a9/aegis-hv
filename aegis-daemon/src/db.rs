use sqlx::sqlite::SqlitePool;
use aegis_common::SecurityEvent;
use chrono::Utc;
use uuid::Uuid;

/// Initializes all database schemas for the Aegis-HV environment.
pub async fn init_db(pool: &SqlitePool) -> anyhow::Result<()> {

    // ─────────────────────────────────────────────
    // SECURITY EVENTS
    // ─────────────────────────────────────────────
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME NOT NULL,
            source TEXT NOT NULL,
            severity TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            action_attempted TEXT NOT NULL,
            reason TEXT NOT NULL,
            mitigated BOOLEAN NOT NULL
        );"
    )
    .execute(pool)
    .await?;

    // ─────────────────────────────────────────────
    // BEHAVIOR LOGS
    // ─────────────────────────────────────────────
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS behavior_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME NOT NULL,
            pid INTEGER NOT NULL,
            agent_id TEXT,
            event_type TEXT NOT NULL,
            details TEXT NOT NULL,
            risk_score REAL DEFAULT 0.0
        );"
    )
    .execute(pool)
    .await?;

    println!("[DB] ✓ Supervisor persistence initialized.");
    Ok(())
}

/// Logs a high-level security event
pub async fn log_event(pool: &SqlitePool, event: &SecurityEvent) -> anyhow::Result<()> {

    sqlx::query!(
        "INSERT INTO security_logs 
        (timestamp, source, severity, agent_id, action_attempted, reason, mitigated)
        VALUES (?, ?, ?, ?, ?, ?, ?)",
        event.timestamp,
        format!("{:?}", event.source),
        format!("{:?}", event.severity),
        event.agent_id.to_string(), // ✅ UUID → string
        event.action_attempted,
        event.reason,
        event.mitigated
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Logs low-level behavior (eBPF / system events)
pub async fn log_behavior(
    pool: &SqlitePool,
    pid: u32,
    agent_id: Option<Uuid>,
    event_type: &str,
    details: &str,
    risk: f64
) -> anyhow::Result<()> {

    let now = Utc::now();

    sqlx::query!(
        "INSERT INTO behavior_logs 
        (timestamp, pid, agent_id, event_type, details, risk_score)
        VALUES (?, ?, ?, ?, ?, ?)",
        now,
        pid,
        agent_id.map(|id| id.to_string()), // ✅ FIXED
        event_type,
        details,
        risk
    )
    .execute(pool)
    .await?;

    Ok(())
}
