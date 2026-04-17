use ed25519_dalek::{Signer, Keypair};
use aegis_common::SecureFrame;
use serde::Serialize;

pub fn sign_frame<T: Serialize>(
    payload: T,
    keypair: &Keypair,
) -> SecureFrame<T> {
    let payload_bytes = serde_json::to_vec(&payload).unwrap();

    let signature = keypair.sign(&payload_bytes);

    SecureFrame {
        payload,
        signature: signature.to_bytes().to_vec(),
        timestamp: chrono::Utc::now().timestamp(),
    }
}