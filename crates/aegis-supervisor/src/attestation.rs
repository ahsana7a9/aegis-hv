use sha2::{Sha256, Digest};
use std::fs;
use anyhow::{Result, anyhow};

pub fn verify_self(expected_hash: &[u8]) -> Result<()> {
    let exe = std::env::current_exe()?;
    let bytes = fs::read(exe)?;

    let mut hasher = Sha256::new();
    hasher.update(bytes);

    let actual = hasher.finalize();

    if actual.as_slice() != expected_hash {
        return Err(anyhow!("Binary integrity check failed"));
    }

    Ok(())
}
