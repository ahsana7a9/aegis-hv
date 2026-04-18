use anyhow::{Result, anyhow};
use std::process::Command;

// ⚠️ Using system TPM2 tools (simpler + stable)

pub fn unseal_kek() -> Result<Vec<u8>> {
    let output = Command::new("tpm2_unseal")
        .arg("-c")
        .arg("/etc/aegis/kek.ctx")
        .output()
        .map_err(|e| anyhow!("Failed to execute TPM unseal: {}", e))?;

    if !output.status.success() {
        return Err(anyhow!("TPM unseal failed"));
    }

    Ok(output.stdout)
}
