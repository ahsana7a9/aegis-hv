use serde::{Serialize, Deserialize};
use crate::AEGIS_AUTH_HASH;

#[derive(Serialize, Deserialize, Debug)]
pub struct SecureFrame<T> {
    pub payload: T,
    pub signature: String, // SHA-256 HMAC or Ed25519 Sig
    pub timestamp: i64,
}

impl<T: Serialize> SecureFrame<T> {
    pub fn wrap(payload: T) -> Self {
        // In a full implementation, this uses your Ed25519 private key
        Self {
            payload,
            signature: AEGIS_AUTH_HASH.to_string(), 
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    pub fn verify(&self) -> bool {
        // Verify signature against the AEGIS_AUTH_HASH
        self.signature == AEGIS_AUTH_HASH
    }
}
