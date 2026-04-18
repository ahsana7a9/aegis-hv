use sqlx::sqlite::SqlitePool;
use aegis_common::SecurityEvent;
use chrono::Utc;
use uuid::Uuid;
use anyhow::{Result, anyhow};
use sha2::{Sha256, Digest};

use crate::signer::LogSigner;
use crate::replicator::LogReplicator;

// ─────────────────────────────────────────────
// INIT DB (SCHEMA + INDEXES)
// ─────────────────────────────────────────────

pub async fn init_db(pool: &SqlitePool) -> Result<()> {

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME NOT NULL,
            source TEXT NOT NULL,
            severity TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            action_attempted TEXT NOT NULL,
            reason TEXT NOT NULL,
            mitigated BOOLEAN NOT NULL,
            prev_hash TEXT,
            hash TEXT NOT NULL,
            signature BLOB NOT NULL
        );"
    )
    .execute(pool)
    .await?;

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

    // INDEXES
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_agent_id ON security_logs(agent_id);")
        .execute(pool).await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_timestamp ON security_logs(timestamp);")
        .execute(pool).await?;

    println!("[DB] ✓ Secure forensic logging initialized");

    Ok(())
}

// ─────────────────────────────────────────────
// HASH UTILS
// ─────────────────────────────────────────────

fn compute_hash(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hex::encode(hasher.finalize())
}

async fn get_last_hash(pool: &SqlitePool) -> Result<Option<String>> {
    let row = sqlx::query!("SELECT hash FROM security_logs ORDER BY id DESC LIMIT 1")
        .fetch_optional(pool)
        .await?;

    Ok(row.map(|r| r.hash))
}

// ─────────────────────────────────────────────
// LOG EVENT (CHAIN + SIGN + REPLICATE)
// ─────────────────────────────────────────────

pub async fn log_event(
    pool: &SqlitePool,
    event: &SecurityEvent,
    signer: &LogSigner,
    replicator: Option<&LogReplicator>,
) -> Result<()> {

    let prev_hash = get_last_hash(pool).await?.unwrap_or_default();

    let data_string = format!(
        "{}|{:?}|{:?}|{}|{}|{}|{}|{}",
        event.timestamp,
        event.source,
        event.severity,
        event.agent_id,
        event.action_attempted,
        event.reason,
        event.mitigated,
        prev_hash
    );

    let hash = compute_hash(&data_string);

    // SIGN HASH
    let signature = signer.sign(hash.as_bytes())?;

    sqlx::query!(
        "INSERT INTO security_logs 
        (timestamp, source, severity, agent_id, action_attempted, reason, mitigated, prev_hash, hash, signature)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        event.timestamp,
        format!("{:?}", event.source),
        format!("{:?}", event.severity),
        event.agent_id.to_string(),
        event.action_attempted,
        event.reason,
        event.mitigated,
        prev_hash,
        hash,
        signature
    )
    .execute(pool)
    .await?;

    // 🔁 NON-BLOCKING REPLICATION
    if let Some(rep) = replicator {
        let _ = rep.send(event).await;
    }

    Ok(())
}

// ─────────────────────────────────────────────
// LOG BEHAVIOR
// ─────────────────────────────────────────────

pub async fn log_behavior(
    pool: &SqlitePool,
    pid: u32,
    agent_id: Option<Uuid>,
    event_type: &str,
    details: &str,
    risk: f64
) -> Result<()> {

    let now = Utc::now();

    sqlx::query!(
        "INSERT INTO behavior_logs 
        (timestamp, pid, agent_id, event_type, details, risk_score)
        VALUES (?, ?, ?, ?, ?, ?)",
        now,
        pid,
        agent_id.map(|id| id.to_string()),
        event_type,
        details,
        risk
    )
    .execute(pool)
    .await?;

    Ok(())
}

// ─────────────────────────────────────────────
// VERIFY LOG CHAIN (TAMPER DETECTION)
// ─────────────────────────────────────────────

pub async fn verify_log_chain(pool: &SqlitePool) -> Result<()> {

    let rows = sqlx::query!(
        "SELECT id, timestamp, source, severity, agent_id, action_attempted, reason, mitigated, prev_hash, hash 
         FROM security_logs ORDER BY id ASC"
    )
    .fetch_all(pool)
    .await?;

    let mut last_hash = String::new();

    for row in rows {

        let prev_hash = row.prev_hash.clone().unwrap_or_default();

        let data_string = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            row.timestamp,
            row.source,
            row.severity,
            row.agent_id,
            row.action_attempted,
            row.reason,
            row.mitigated,
            prev_hash
        );

        let computed = compute_hash(&data_string);

        if computed != row.hash {
            return Err(anyhow!("🚨 LOG TAMPERING DETECTED at ID {}", row.id));
        }

        if prev_hash != last_hash {
            return Err(anyhow!("🚨 HASH CHAIN BROKEN at ID {}", row.id));
        }

        last_hash = row.hash.clone();
    }

    println!("[DB] ✓ Log chain integrity verified");

    Ok(())
}
