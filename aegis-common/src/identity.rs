use serde::{Serialize, Deserialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentIdentity {
    pub id: Uuid,
    pub role: String,
    pub public_key: Vec<u8>,
    pub metadata: AgentMetadata,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentMetadata {
    pub version: String,
    pub created_at: i64,
}
