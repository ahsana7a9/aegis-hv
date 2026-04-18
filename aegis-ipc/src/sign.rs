use ed25519_dalek::{Signer, Keypair};
use aegis_common::SecureFrame;
use serde::Serialize;
use rand::RngCore;

pub struct SignerState {
    pub keypair: Keypair,
    pub sequence: u64,
}

pub fn sign_frame<T: Serialize>(&mut self, payload: T) -> SecureFrame<T> {
    use rand::RngCore;

    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let timestamp = chrono::Utc::now().timestamp();

    self.sequence += 1;
    let sequence = self.sequence;

    // 🔐 Build signed message (CRITICAL)
    let mut data = serde_json::to_vec(&payload).unwrap();
    data.extend(&nonce);
    data.extend(&sequence.to_le_bytes());
    data.extend(&timestamp.to_le_bytes());

    let signature = self.keypair.sign(&data);

    SecureFrame {
        payload,
        signature: signature.to_bytes().to_vec(),
        timestamp,
        nonce,
        sequence,
    }
}
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
