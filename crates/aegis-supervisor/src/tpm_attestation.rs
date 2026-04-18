use anyhow::{Result, anyhow};
use std::process::Command;

pub fn attest() -> Result<()> {

    let output = Command::new("tpm2_quote")
        .args([
            "-C", "o",
            "-l", "sha256:0,1,2,3",
            "-q", "aegis_nonce",
            "-m", "quote.bin",
            "-s", "sig.bin",
        ])
        .output()?;

    if !output.status.success() {
        return Err(anyhow!("TPM attestation failed"));
    }

    Ok(())
}
