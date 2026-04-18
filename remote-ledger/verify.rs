use anyhow::{Result, anyhow};
use blake3;
use ed25519_dalek::{PublicKey, Signature, Verifier};
use serde::{Deserialize, Serialize};

// MUST match supervisor exactly
const LOG_DOMAIN: &[u8] = b"AEGIS_LOG_CHAIN_V2";

// ─────────────────────────────────────────────
// ENVELOPE STRUCTURE (FROM SUPERVISOR)
// ─────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct LedgerEnvelope {
    pub index: u64,
    pub event: serde_json::Value,
    pub hash: String,
    pub signature: String, // base64
}

// ─────────────────────────────────────────────
// HASH
// ─────────────────────────────────────────────

fn compute_hash(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

// ─────────────────────────────────────────────
// CANONICAL BYTES (MUST MATCH SUPERVISOR)
// ─────────────────────────────────────────────

fn canonical_bytes(
    event: &serde_json::Value,
    prev_hash: &str,
    index: u64,
) -> Result<Vec<u8>> {

    let mut data = Vec::new();

    data.extend(LOG_DOMAIN);
    data.extend(&index.to_le_bytes());

    let obj = event.as_object()
        .ok_or_else(|| anyhow!("Invalid event format"))?;

    // STRICT FIELD ORDER
    data.extend(obj["timestamp"].as_str().unwrap().as_bytes());
    data.extend(obj["source"].as_str().unwrap().as_bytes());
    data.extend(obj["severity"].as_str().unwrap().as_bytes());
    data.extend(obj["agent_id"].as_str().unwrap().as_bytes());
    data.extend(obj["action_attempted"].as_str().unwrap().as_bytes());
    data.extend(obj["reason"].as_str().unwrap().as_bytes());
    data.push(obj["mitigated"].as_bool().unwrap() as u8);

    data.extend(prev_hash.as_bytes());

    Ok(data)
}

// ─────────────────────────────────────────────
// VERIFY FULL ENTRY
// ─────────────────────────────────────────────

pub fn verify_entry(
    envelope: &LedgerEnvelope,
    last_index: u64,
    last_hash: &str,
    pubkey: &PublicKey,
) -> Result<()> {

    // ────────────────
    // 1. INDEX CHECK
    // ────────────────
    if envelope.index != last_index + 1 {
        return Err(anyhow!(
            "🚨 INVALID INDEX: expected {}, got {}",
            last_index + 1,
            envelope.index
        ));
    }

    // ────────────────
    // 2. REBUILD HASH
    // ────────────────
    let data = canonical_bytes(
        &envelope.event,
        last_hash,
        envelope.index
    )?;

    let computed_hash = compute_hash(&data);

    if computed_hash != envelope.hash {
        return Err(anyhow!(
            "🚨 HASH MISMATCH at index {}",
            envelope.index
        ));
    }

    // ────────────────
    // 3. VERIFY SIGNATURE
    // ────────────────
    let sig_bytes = base64::decode(&envelope.signature)
        .map_err(|_| anyhow!("Invalid base64 signature"))?;

    let sig = Signature::from_bytes(&sig_bytes)
        .map_err(|_| anyhow!("Invalid signature format"))?;

    pubkey
        .verify(envelope.hash.as_bytes(), &sig)
        .map_err(|_| anyhow!("🚨 SIGNATURE INVALID"))?;

    // ────────────────
    // 4. FORK CHECK
    // ────────────────
    // If someone tries to replay with same index but different hash,
    // this is already blocked by index + chain logic above.
    // So no extra logic needed here.

    Ok(())
}
