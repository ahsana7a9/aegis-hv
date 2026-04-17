use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct SecureFrame<T> {
    pub payload: T,
    pub signature: Vec<u8>,   // raw signature bytes
    pub timestamp: i64,
}