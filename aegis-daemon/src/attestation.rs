use sha2::{Sha256, Digest};
use std::fs;
use std::path::Path;
use anyhow::anyhow;

/// Binary attestation module for runtime integrity verification
/// This prevents execution of tampered or unauthorized daemon binaries
pub struct BinaryAttestation;

impl BinaryAttestation {
    /// Verifies the integrity of the running daemon binary against a known-good hash
    pub fn verify_self(expected_hash: &str) -> anyhow::Result<()> {
        let exe_path = std::env::current_exe()
            .map_err(|e| anyhow!("Failed to get current executable path: {}", e))?;

        if !exe_path.exists() {
            return Err(anyhow!("Executable path does not exist: {:?}", exe_path));
        }

        let binary_data = fs::read(&exe_path)
            .map_err(|e| anyhow!("Failed to read binary file {:?}: {}", exe_path, e))?;

        let mut hasher = Sha256::new();
        hasher.update(&binary_data);
        let computed_hash = format!("{:x}", hasher.finalize());

        if computed_hash != expected_hash {
            return Err(anyhow!(
                "Binary integrity verification FAILED!\n\
                 Expected: {}\n\
                 Got:      {}\n\
                 This daemon binary has been modified or is unauthorized.",
                expected_hash,
                computed_hash
            ));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&exe_path)?;
            let mode = metadata.permissions().mode();
            
            if (mode & 0o002) != 0 {
                return Err(anyhow!(
                    "Binary file has insecure permissions: {:o} (world-writable)",
                    mode
                ));
            }
        }

        println!("[AEGIS-ATTESTATION] ✓ Binary integrity verified successfully");
        Ok(())
    }

    pub fn compute_hash(binary_path: &str) -> anyhow::Result<String> {
        let data = fs::read(binary_path)
            .map_err(|e| anyhow!("Failed to read binary: {}", e))?;
        
        let mut hasher = Sha256::new();
        hasher.update(&data);
        Ok(format!("{:x}", hasher.finalize()))
    }

    #[cfg(unix)]
    pub fn verify_ownership(binary_path: &str) -> anyhow::Result<()> {
        use std::os::unix::fs::MetadataExt;
        
        let metadata = fs::metadata(binary_path)?;
        let uid = metadata.uid();
        
        if uid != 0 {
            return Err(anyhow!(
                "Binary is owned by UID {}, expected 0 (root)",
                uid
            ));
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_computation() {
        // Tests would go here
    }
}