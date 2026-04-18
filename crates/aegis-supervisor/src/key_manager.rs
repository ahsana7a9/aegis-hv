use aes_gcm::{Aes256Gcm, aead::{Aead, KeyInit}};
use anyhow::{Result, anyhow};
use aes_gcm::Nonce;
use rand::RngCore;

pub struct KeyManager {
    pub kek: Vec<u8>, // from TPM
}

impl KeyManager {

    pub fn new(kek: Vec<u8>) -> Self {
        Self { kek }
    }

    // 🔐 Generate new DEK
    pub fn generate_dek(&self) -> [u8; 32] {
        let mut dek = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut dek);
        dek
    }

    // 🔒 Encrypt DEK with KEK
    pub fn wrap_dek(&self, dek: &[u8]) -> Result<(Vec<u8>, [u8; 12])> {
        let cipher = Aes256Gcm::new_from_slice(&self.kek)?;

        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        let encrypted = cipher.encrypt(
            Nonce::from_slice(&nonce),
            dek,
        ).map_err(|_| anyhow!("DEK encryption failed"))?;

        Ok((encrypted, nonce))
    }

    // 🔓 Decrypt DEK
    pub fn unwrap_dek(&self, encrypted: &[u8], nonce: &[u8]) -> Result<[u8; 32]> {
        let cipher = Aes256Gcm::new_from_slice(&self.kek)?;

        let decrypted = cipher.decrypt(
            Nonce::from_slice(nonce),
            encrypted,
        ).map_err(|_| anyhow!("DEK decryption failed"))?;

        Ok(decrypted.try_into().map_err(|_| anyhow!("Invalid DEK size"))?)
    }
}
