use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use aes_gcm::aead::rand_core::RngCore;
use std::{fs, path::PathBuf};
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use std::collections::HashMap;
use aegis_common::AgentIdentity;

// ─────────────────────────────────────────────────────────────
// FILE FORMAT (ENCRYPTED BLOB)
// ─────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct EncryptedRegistry {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────
// REGISTRY STRUCTURE (IN MEMORY)
// ─────────────────────────────────────────────────────────────

pub struct SecureIdentityRegistry {
    path: PathBuf,
    key: [u8; 32],
    identities: HashMap<Uuid, AgentIdentity>,
}

impl SecureIdentityRegistry {

    // ─────────────────────────────────────────────────────────
    // INIT
    // ─────────────────────────────────────────────────────────
    pub fn new(path: PathBuf, key: [u8; 32]) -> Self {
        Self {
            path,
            key,
            identities: HashMap::new(),
        }
    }

    // ─────────────────────────────────────────────────────────
    // LOAD FROM DISK
    // ─────────────────────────────────────────────────────────
    pub fn load(&mut self) -> Result<()> {
        if !self.path.exists() {
            return Ok(()); // first run
        }

        let data = fs::read(&self.path)?;

        let encrypted: EncryptedRegistry = serde_json::from_slice(&data)?;

        let cipher = Aes256Gcm::new_from_slice(&self.key)?;
        let nonce = Nonce::from_slice(&encrypted.nonce);

        let decrypted = cipher.decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|_| anyhow!("Decryption failed (wrong key or tampered data)"))?;

        self.identities = serde_json::from_slice(&decrypted)?;

        Ok(())
    }

    // ─────────────────────────────────────────────────────────
    // SAVE (ENCRYPTED + ATOMIC)
    // ─────────────────────────────────────────────────────────
    pub fn save(&self) -> Result<()> {
        let plaintext = serde_json::to_vec(&self.identities)?;

        let cipher = Aes256Gcm::new_from_slice(&self.key)?;

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
            .map_err(|_| anyhow!("Encryption failed"))?;

        let blob = EncryptedRegistry {
            nonce: nonce_bytes.to_vec(),
            ciphertext,
        };

        let serialized = serde_json::to_vec(&blob)?;

        // 🔒 Atomic write
        let tmp_path = self.path.with_extension("tmp");
        fs::write(&tmp_path, serialized)?;
        fs::rename(tmp_path, &self.path)?;

        Ok(())
    }

    // ─────────────────────────────────────────────────────────
    // CRUD OPERATIONS
    // ─────────────────────────────────────────────────────────

    pub fn register(&mut self, identity: AgentIdentity) {
        self.identities.insert(identity.id, identity);
    }

    pub fn get(&self, id: &Uuid) -> Option<&AgentIdentity> {
        self.identities.get(id)
    }

    pub fn get_mut(&mut self, id: &Uuid) -> Option<&mut AgentIdentity> {
        self.identities.get_mut(id)
    }

    pub fn get_active_key(&self, id: &Uuid) -> Option<[u8; 32]> {
        self.identities.get(id)?
            .keys.iter()
            .find(|k| k.active)
            .map(|k| k.key)
    }
}
