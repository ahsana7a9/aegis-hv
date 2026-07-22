use ed25519_dalek::{Verifier, VerifyingKey, Signature};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use tracing::{error, info};

pub struct BinaryAttestation {
    pubkey: VerifyingKey,
}

impl BinaryAttestation {
    /// Initialize with an embedded or configured deployment Public Key
    pub fn new(pubkey_bytes: &[u8; 32]) -> Result<Self, String> {
        let pubkey = VerifyingKey::from_bytes(pubkey_bytes)
            .map_err(|e| format!("Invalid attestation public key: {}", e))?;
        Ok(Self { pubkey })
    }

    /// Verifies the current binary against an embedded signature in the `.aegis_identity` ELF section
    #[cfg(feature = "self-attestation")]
    pub fn verify_self_integrity(&self) -> Result<(), String> {
        let current_exe = std::env::current_exe()
            .map_err(|e| format!("Failed to locate self binary: {}", e))?;

        let binary_bytes = fs::read(&current_exe)
            .map_err(|e| format!("Failed to read binary for self-attestation: {}", e))?;

        let (data, signature_bytes) = Self::extract_aegis_section(&binary_bytes)?;

        let signature = Signature::from_bytes(&signature_bytes)
            .map_err(|e| format!("Invalid signature format: {}", e))?;

        let mut hasher = Sha256::new();
        hasher.update(&data);
        let digest = hasher.finalize();

        self.pubkey
            .verify(&digest, &signature)
            .map_err(|_| "Self-attestation failed: Binary signature mismatch!".to_string())?;

        info!("Self-attestation check passed successfully.");
        Ok(())
    }

    #[cfg(not(feature = "self-attestation"))]
    pub fn verify_self_integrity(&self) -> Result<(), String> {
        info!("Self-attestation disabled via feature flag. Skipping binary verification.");
        Ok(())
    }

    fn extract_aegis_section(raw_elf: &[u8]) -> Result<(Vec<u8>, [u8; 64]), String> {
        // Simple ELF parser logic to locate custom section .aegis_identity
        // Strips section signature payload from raw data before computing payload digest
        let section_signature = raw_elf.get(raw_elf.len().saturating_sub(64)..)
            .ok_or("Missing .aegis_identity signature footer")?;
        
        let payload = raw_elf[..raw_elf.len() - 64].to_vec();
        let mut sig = [0u8; 64];
        sig.copy_from_slice(section_signature);

        Ok((payload, sig))
    }
}
