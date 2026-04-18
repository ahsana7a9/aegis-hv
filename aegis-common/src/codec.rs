use serde::{Serialize, Deserialize};
use blake3;
use ed25519_dalek::Signer;

const DOMAIN: &[u8] = b"AEGIS_SECURE_FRAME_V1";
const VERSION: u8 = 1;

#[derive(Serialize, Deserialize, Debug)]
pub struct SecureFrame<T> {
    pub payload: T,
    pub signature: Vec<u8>,
    pub timestamp: i64,
    pub nonce: Vec<u8>,
    pub sequence: u64,
}

impl<T: Serialize> SecureFrame<T> {

    fn canonical_bytes(payload: &T, nonce: &[u8], seq: u64, ts: i64) -> Vec<u8> {
        let mut data = Vec::new();

        data.extend(DOMAIN);
        data.push(VERSION);

        data.extend(serde_json::to_vec(payload).unwrap());
        data.extend(nonce);
        data.extend(&seq.to_le_bytes());
        data.extend(&ts.to_le_bytes());

        data
    }

    pub fn wrap_signed(
        payload: T,
        keypair: &ed25519_dalek::Keypair,
        nonce: Vec<u8>,
        sequence: u64,
    ) -> Self {

        let timestamp = chrono::Utc::now().timestamp();

        let data = Self::canonical_bytes(&payload, &nonce, sequence, timestamp);

        // 🔥 BLAKE3 HASH
        let hash = blake3::hash(&data);

        // 🔐 SIGN HASH (NOT RAW DATA)
        let signature = keypair.sign(hash.as_bytes()).to_bytes().to_vec();

        Self {
            payload,
            signature,
            timestamp,
            nonce,
            sequence,
        }
    }
}
