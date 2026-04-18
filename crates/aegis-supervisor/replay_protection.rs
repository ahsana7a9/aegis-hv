use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::{anyhow, Result};

pub struct ReplayProtector {
    seen_nonces: HashSet<[u8; 16]>,
    last_sequence: u64,
    max_drift_seconds: i64,
}

impl ReplayProtector {
    pub fn new() -> Self {
        Self {
            seen_nonces: HashSet::new(),
            last_sequence: 0,
            max_drift_seconds: 30, // allow 30s clock drift
        }
    }

    pub fn verify(&mut self, nonce: [u8; 16], sequence: u64, timestamp: i64) -> Result<()> {
        // ───────────── TIMESTAMP CHECK ─────────────
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        if (now - timestamp).abs() > self.max_drift_seconds {
            return Err(anyhow!("Timestamp out of allowed range (replay attempt?)"));
        }

        // ───────────── NONCE CHECK ─────────────
        if self.seen_nonces.contains(&nonce) {
            return Err(anyhow!("Replay detected: nonce already used"));
        }

        self.seen_nonces.insert(nonce);

        // ───────────── SEQUENCE CHECK ─────────────
        if sequence <= self.last_sequence {
            return Err(anyhow!("Out-of-order or replayed sequence"));
        }

        self.last_sequence = sequence;

        Ok(())
    }
}
