use ed25519_dalek::{Keypair, Signer};
use anyhow::Result;

use crate::tpm_signer::tpm_sign;

pub enum SignMode {
    TPM,
    Software(Keypair),
}

pub struct LogSigner {
    mode: SignMode,
}

impl LogSigner {
    pub fn new_tpm() -> Self {
        Self { mode: SignMode::TPM }
    }

    pub fn new_software(keypair: Keypair) -> Self {
        Self { mode: SignMode::Software(keypair) }
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        match &self.mode {
            SignMode::TPM => tpm_sign(message),
            SignMode::Software(kp) => Ok(kp.sign(message).to_bytes().to_vec()),
        }
    }
}
