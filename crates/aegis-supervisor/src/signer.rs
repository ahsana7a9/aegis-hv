use ed25519_dalek::{Keypair, Signer, Signature};
use anyhow::Result;

pub struct LogSigner {
    keypair: Keypair,
}

impl LogSigner {
    pub fn new(keypair: Keypair) -> Self {
        Self { keypair }
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.keypair.sign(message).to_bytes().to_vec()
    }
}
