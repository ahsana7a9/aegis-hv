use anyhow::{Result, anyhow};
use std::process::Command;

/// Signs a message hash using TPM-resident key
/// Expects a loaded key context at /etc/aegis/sign.ctx
pub fn tpm_sign(hash: &[u8]) -> Result<Vec<u8>> {
    // Write hash to a temp file
    let tmp_in = "/tmp/aegis_hash.bin";
    let tmp_out = "/tmp/aegis_sig.bin";
    std::fs::write(tmp_in, hash)?;

    let status = Command::new("tpm2_sign")
        .args([
            "-c", "/etc/aegis/sign.ctx",
            "-g", "sha256",
            "-d", tmp_in,
            "-o", tmp_out,
        ])
        .status()
        .map_err(|e| anyhow!("Failed to execute tpm2_sign: {}", e))?;

    if !status.success() {
        return Err(anyhow!("TPM signing failed"));
    }

    let sig = std::fs::read(tmp_out)?;
    Ok(sig)
}
