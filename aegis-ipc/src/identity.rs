use aegis_common::{AgentIdentity, AgentMetadata, PublicKeyEntry, Role};
use uuid::Uuid;

pub fn create_identity(role: Role, public_key: [u8; 32]) -> AgentIdentity {
    AgentIdentity {
        id: Uuid::new_v4(),
        role,
        keys: vec![PublicKeyEntry {
            key: public_key,
            version: 1,
            active: true,
        }],
        metadata: AgentMetadata {
            version: "1.0.0".to_string(),
            created_at: chrono::Utc::now().timestamp(),
        },
    }
}
