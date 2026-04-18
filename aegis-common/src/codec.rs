use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct SecureFrame<T> {
    pub payload: T,
    pub signature: Vec<u8>,
    pub timestamp: i64,
    pub nonce: [u8; 16],   // 128-bit random
    pub sequence: u64,     // monotonic per sender
}
