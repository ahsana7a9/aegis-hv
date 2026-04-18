use serde::{Serialize, Deserialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentIdentity {
    pub id: Uuid,
    pub role: Role,
    pub keys: Vec<PublicKeyEntry>,
    pub metadata: AgentMetadata,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PublicKeyEntry {
    pub key: [u8; 32],     // Ed25519 public key
    pub version: u32,
    pub active: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentMetadata {
    pub version: String,
    pub created_at: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum Role {
    Supervisor,
    Enforcer,
    Monitor,
    Admin,
    ReadOnly,
}
