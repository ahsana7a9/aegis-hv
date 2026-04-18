use std::collections::HashMap;
use uuid::Uuid;
use aegis_common::AgentIdentity;

pub struct IdentityRegistry {
    identities: HashMap<Uuid, AgentIdentity>,
}

impl IdentityRegistry {
    pub fn new() -> Self {
        Self {
            identities: HashMap::new(),
        }
    }

    pub fn register(&mut self, identity: AgentIdentity) {
        self.identities.insert(identity.id, identity);
    }

    pub fn get(&self, id: &Uuid) -> Option<&AgentIdentity> {
        self.identities.get(id)
    }

    pub fn get_active_key(&self, id: &Uuid) -> Option<[u8; 32]> {
        self.identities.get(id)?
            .keys.iter()
            .find(|k| k.active)
            .map(|k| k.key)
    }
}
