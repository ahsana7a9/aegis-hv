use sqlx::sqlite::SqlitePool;
use aegis_common::SecurityEvent;

/// Initializes the database schema if it doesn't exist.
pub async fn init_db(pool: &SqlitePool) -> anyhow::Result<()> {
    sqlx::query!(
        "CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME NOT NULL,
            source TEXT NOT NULL,
            severity TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            reason TEXT NOT NULL,
            mitigated BOOLEAN NOT NULL
        )"
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Logs a security event to the SQLite database for historical auditing.
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
