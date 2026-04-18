use ed25519_dalek::{Signer, Keypair};
use aegis_common::SecureFrame;
use serde::Serialize;
use rand::RngCore;

pub struct SignerState {
    pub keypair: Keypair,
    pub sequence: u64,
}

impl SignerState {
    pub fn sign_frame<T: Serialize>(&mut self, payload: T) -> SecureFrame<T> {
        let payload_bytes = serde_json::to_vec(&payload).unwrap();

        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        let signature = self.keypair.sign(&payload_bytes);

        self.sequence += 1;

        SecureFrame {
            payload,
            signature: signature.to_bytes().to_vec(),
            timestamp: chrono::Utc::now().timestamp(),
            nonce,
            sequence: self.sequence,
        }
    }
}
