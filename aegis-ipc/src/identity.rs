use aegis_common::{AgentIdentity, AgentMetadata};
use uuid::Uuid;

pub fn create_identity(role: &str, public_key: Vec<u8>) -> AgentIdentity {
    AgentIdentity {
        id: Uuid::new_v4(),
        role: role.to_string(),
        public_key,
        metadata: AgentMetadata {
            version: "1.0.0-Genesis".to_string(),
            created_at: chrono::Utc::now().timestamp(),
        },
    }
}
