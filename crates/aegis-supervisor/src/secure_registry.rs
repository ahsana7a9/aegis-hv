use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use aes_gcm::aead::rand_core::RngCore;
use std::{fs, path::PathBuf};
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use std::collections::HashMap;
use aegis_common::AgentIdentity;

use crate::key_manager::KeyManager;
use crate::tpm::unseal_kek;

// ─────────────────────────────────────────────────────────────
// STORED FORMAT (ENVELOPE ENCRYPTION)
// ─────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct StoredRegistry {
    wrapped_dek: Vec<u8>,
    dek_nonce: Vec<u8>,
    data_nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────
// REGISTRY
// ─────────────────────────────────────────────────────────────

pub struct SecureIdentityRegistry {
    path: PathBuf,
    dek: Option<[u8; 32]>,
    identities: HashMap<Uuid, AgentIdentity>,
}

impl SecureIdentityRegistry {

    // INIT
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            dek: None,
            identities: HashMap::new(),
        }
    }

    // ─────────────────────────────────────────────────────────
    // LOAD
    // ─────────────────────────────────────────────────────────
    pub fn load(&mut self) -> Result<()> {

        if !self.path.exists() {
            return Ok(()); // first run
        }

        let data = fs::read(&self.path)?;
        let stored: StoredRegistry = serde_json::from_slice(&data)?;

        // 🔴 STEP 1: Unseal KEK (TPM)
        let kek = unseal_kek()?;
        let km = KeyManager::new(kek);

        // 🔴 STEP 2: Unwrap DEK
        let dek = km.unwrap_dek(&stored.wrapped_dek, &stored.dek_nonce)?;

        // 🔴 STEP 3: Decrypt registry
        let cipher = Aes256Gcm::new_from_slice(&dek)?;
        let nonce = Nonce::from_slice(&stored.data_nonce);

        let decrypted = cipher.decrypt(nonce, stored.ciphertext.as_ref())
            .map_err(|_| anyhow!("Registry decryption failed"))?;

        self.identities = serde_json::from_slice(&decrypted)?;
        self.dek = Some(dek);

        Ok(())
    }

    // ─────────────────────────────────────────────────────────
    // SAVE
    // ─────────────────────────────────────────────────────────
    pub fn save(&mut self) -> Result<()> {

        // 🔴 STEP 1: Ensure DEK exists
        let dek = match self.dek {
            Some(k) => k,
            None => {
                let kek = unseal_kek()?;
                let km = KeyManager::new(kek);
                let new_dek = km.generate_dek();
                self.dek = Some(new_dek);
                new_dek
            }
        };

        let plaintext = serde_json::to_vec(&self.identities)?;

        let cipher = Aes256Gcm::new_from_slice(&dek)?;

        // 🔴 DATA NONCE
        let mut data_nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut data_nonce);

        let ciphertext = cipher.encrypt(
            Nonce::from_slice(&data_nonce),
            plaintext.as_ref()
        ).map_err(|_| anyhow!("Encryption failed"))?;

        // 🔴 STEP 2: Wrap DEK with KEK
        let kek = unseal_kek()?;
        let km = KeyManager::new(kek);

        let (wrapped_dek, dek_nonce) = km.wrap_dek(&dek)?;

        let blob = StoredRegistry {
            wrapped_dek,
            dek_nonce: dek_nonce.to_vec(),
            data_nonce: data_nonce.to_vec(),
            ciphertext,
        };

        let serialized = serde_json::to_vec(&blob)?;

        // 🔒 ATOMIC WRITE
        let tmp_path = self.path.with_extension("tmp");
        fs::write(&tmp_path, serialized)?;
        fs::rename(tmp_path, &self.path)?;

        Ok(())
    }

    // ─────────────────────────────────────────────────────────
    // ROTATE DEK (SAFE)
    // ─────────────────────────────────────────────────────────
    pub fn rotate_dek(&mut self) -> Result<()> {
        let kek = unseal_kek()?;
        let km = KeyManager::new(kek);

        let new_dek = km.generate_dek();
        self.dek = Some(new_dek);

        // Save will re-encrypt everything
        self.save()
    }

    // ─────────────────────────────────────────────────────────
    // CRUD
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
