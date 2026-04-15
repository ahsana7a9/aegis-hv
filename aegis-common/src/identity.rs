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

impl AgentIdentity {
    pub fn new(role: &str, pubkey: Vec<u8>) -> Self {
        Self {
            id: Uuid::new_v4(),
            role: role.to_string(),
            public_key: pubkey,
            metadata: AgentMetadata {
                version: "1.0.0-Genesis".to_string(),
                created_at: chrono::Utc::now().timestamp(),
            },
        }
    }
}
