use sqlx::sqlite::SqlitePool;

pub async fn log_event(pool: &SqlitePool, event: &SecurityEvent) -> anyhow::Result<()> {
    sqlx::query!(
        "INSERT INTO security_logs (timestamp, severity, reason) VALUES (?, ?, ?)",
        event.timestamp,
        format!("{:?}", event.severity),
        event.reason
    )
    .execute(pool)
    .await?;
    Ok(())
}
