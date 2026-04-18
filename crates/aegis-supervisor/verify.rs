use anyhow::{Result, anyhow};
use ed25519_dalek::{PublicKey, Signature, Verifier};
use blake3;
use serde::Serialize;
use aegis_common::SecureFrame;
use crate::replay_protection::ReplayProtector;
use std::time::{SystemTime, UNIX_EPOCH};

const DOMAIN: &[u8] = b"AEGIS_SECURE_FRAME_V1";
const VERSION: u8 = 1;
const MAX_SKEW: i64 = 30;

fn canonical_bytes<T: Serialize>(
    payload: &T,
    nonce: &[u8],
    seq: u64,
    ts: i64
) -> Result<Vec<u8>> {

    let mut data = Vec::new();

    data.extend(DOMAIN);
    data.push(VERSION);

    data.extend(serde_json::to_vec(payload)?);
    data.extend(nonce);
    data.extend(&seq.to_le_bytes());
    data.extend(&ts.to_le_bytes());

    Ok(data)
}

pub fn verify_full<T: Serialize>(
    frame: &SecureFrame<T>,
    pubkey: &PublicKey,
    replay: &mut ReplayProtector,
) -> Result<()> {

    // STRUCTURE
    if frame.signature.len() != 64 {
        return Err(anyhow!("Invalid signature length"));
    }

    // TIMESTAMP
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs() as i64;

    if (now - frame.timestamp).abs() > MAX_SKEW {
        return Err(anyhow!("Timestamp out of range"));
    }

    // CANONICAL DATA
    let data = canonical_bytes(
        &frame.payload,
        &frame.nonce,
        frame.sequence,
        frame.timestamp
    )?;

    // 🔥 HASH
    let hash = blake3::hash(&data);

    // VERIFY
    let sig = Signature::from_bytes(&frame.signature)?;
    pubkey
        .verify(hash.as_bytes(), &sig)
        .map_err(|_| anyhow!("Signature verification failed"))?;

    // REPLAY PROTECTION
    replay.verify(frame.nonce.clone(), frame.sequence, frame.timestamp)?;

    Ok(())
}
