use sqlx::sqlite::SqlitePool;
use aegis_common::SecurityEvent;
use chrono::Utc;
use uuid::Uuid;
use anyhow::{Result, anyhow};
use blake3;

use crate::signer::LogSigner;
use crate::replicator::LogReplicator;

// ─────────────────────────────────────────────
// DOMAIN SEPARATION
// ─────────────────────────────────────────────

const LOG_DOMAIN: &[u8] = b"AEGIS_LOG_CHAIN_V2";

// ─────────────────────────────────────────────
// INIT DB
// ─────────────────────────────────────────────

pub async fn init_db(pool: &SqlitePool) -> Result<()> {

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_index INTEGER NOT NULL UNIQUE,
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

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_agent_id ON security_logs(agent_id);")
        .execute(pool).await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_timestamp ON security_logs(timestamp);")
        .execute(pool).await?;

    println!("[DB] ✓ V2 forensic ledger initialized");

    Ok(())
}

// ─────────────────────────────────────────────
// HASH
// ─────────────────────────────────────────────

fn compute_hash(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

// ─────────────────────────────────────────────
// CANONICAL ENCODING (STRICT)
// ─────────────────────────────────────────────

fn canonical_bytes(
    event: &SecurityEvent,
    prev_hash: &str,
    index: u64,
) -> Vec<u8> {

    let mut data = Vec::with_capacity(256);

    data.extend(LOG_DOMAIN);
    data.extend(&index.to_le_bytes());

    data.extend(event.timestamp.to_rfc3339().as_bytes());
    data.extend(format!("{:?}", event.source).as_bytes());
    data.extend(format!("{:?}", event.severity).as_bytes());
    data.extend(event.agent_id.as_bytes());
    data.extend(event.action_attempted.as_bytes());
    data.extend(event.reason.as_bytes());

    data.push(event.mitigated as u8);

    data.extend(prev_hash.as_bytes());

    data
}

// ─────────────────────────────────────────────
// STATE
// ─────────────────────────────────────────────

async fn get_last_state(pool: &SqlitePool) -> Result<(u64, String)> {

    let row = sqlx::query!(
        "SELECT log_index, hash FROM security_logs ORDER BY id DESC LIMIT 1"
    )
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => Ok((r.log_index as u64, r.hash)),
        None => Ok((0, String::new())),
    }
}

// ─────────────────────────────────────────────
// LOG EVENT (STRICT + QUORUM ENFORCED)
// ─────────────────────────────────────────────

pub async fn log_event(
    pool: &SqlitePool,
    event: &SecurityEvent,
    signer: &LogSigner,
    replicator: Option<&LogReplicator>,
) -> Result<()> {

    let mut tx = pool.begin().await?;

    let (last_index, prev_hash) = get_last_state(pool).await?;
    let index = last_index + 1;

    // Canonical encoding
    let data = canonical_bytes(event, &prev_hash, index);

    // Hash
    let hash = compute_hash(&data);

    // Sign HASH (hash-then-sign)
    let signature = signer.sign(hash.as_bytes())?;

    // Store locally FIRST (atomic)
    sqlx::query!(
        "INSERT INTO security_logs 
        (log_index, timestamp, source, severity, agent_id, action_attempted, reason, mitigated, prev_hash, hash, signature)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        index as i64,
        event.timestamp,
        format!("{:?}", event.source),
        format!("{:?}", event.severity),
        event.agent_id,
        event.action_attempted,
        event.reason,
        event.mitigated,
        prev_hash,
        hash,
        signature
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    // 🔴 FAIL-CLOSED REPLICATION (QUORUM REQUIRED)
    if let Some(rep) = replicator {

        let envelope = serde_json::json!({
            "index": index,
            "event": event,
            "hash": hash,
            "signature": base64::encode(signature),
        });

        // 🔥 MUST SUCCEED (NO SILENT FAIL)
        rep.replicate(&envelope).await?;
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
// VERIFY CHAIN (STRICT + SIGNATURE)
// ─────────────────────────────────────────────

pub async fn verify_log_chain(
    pool: &SqlitePool,
    pubkey: &ed25519_dalek::PublicKey
) -> Result<()> {

    let rows = sqlx::query!(
        "SELECT log_index, timestamp, source, severity, agent_id, action_attempted, reason, mitigated, prev_hash, hash, signature 
         FROM security_logs ORDER BY log_index ASC"
    )
    .fetch_all(pool)
    .await?;

    let mut last_hash = String::new();

    for row in rows {

        let event = SecurityEvent {
            timestamp: row.timestamp,
            source: row.source.parse().unwrap_or_default(),
            severity: row.severity.parse().unwrap_or_default(),
            agent_id: row.agent_id.clone(),
            action_attempted: row.action_attempted.clone(),
            reason: row.reason.clone(),
            mitigated: row.mitigated,
        };

        let data = canonical_bytes(
            &event,
            &row.prev_hash.clone().unwrap_or_default(),
            row.log_index as u64
        );

        let computed = compute_hash(&data);

        if computed != row.hash {
            return Err(anyhow!("🚨 TAMPERING at index {}", row.log_index));
        }

        // Verify signature
        let sig = ed25519_dalek::Signature::from_bytes(&row.signature)?;
        pubkey
            .verify(row.hash.as_bytes(), &sig)
            .map_err(|_| anyhow!("🚨 SIGNATURE FORGERY at {}", row.log_index))?;

        if row.prev_hash.unwrap_or_default() != last_hash {
            return Err(anyhow!("🚨 CHAIN BREAK at {}", row.log_index));
        }

        last_hash = row.hash.clone();
    }

    println!("[DB] ✓ Ledger integrity VERIFIED");

    Ok(())
}
