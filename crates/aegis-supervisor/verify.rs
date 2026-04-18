use anyhow::anyhow;
use ed25519_dalek::{Verifier, PublicKey, Signature};
use aegis_common::SecureFrame;
use serde::Serialize;
use crate::replay_protection::ReplayProtector;

pub fn verify_full<T: Serialize>(
    frame: &SecureFrame<T>,
    public_key: &PublicKey,
    replay: &mut ReplayProtector,
) -> anyhow::Result<()> {

    // 1. Signature (FULL DATA)
    verify_frame(frame, public_key)?;

    // 2. Replay protection
    replay.verify(frame.nonce, frame.sequence, frame.timestamp)?;

    Ok(())
}

pub fn verify_frame<T: Serialize>(
    frame: &SecureFrame<T>,
    public_key: &PublicKey,
) -> anyhow::Result<()> {

    // 🔐 MUST MATCH SIGNING SIDE EXACTLY
    let mut data = serde_json::to_vec(&frame.payload)?;

    data.extend(&frame.nonce);
    data.extend(&frame.sequence.to_le_bytes());
    data.extend(&frame.timestamp.to_le_bytes());

    let sig = Signature::from_bytes(&frame.signature)
        .map_err(|_| anyhow!("Invalid signature format"))?;

    public_key
        .verify(&data, &sig)
        .map_err(|_| anyhow!("Signature verification failed"))?;

    Ok(())
}
