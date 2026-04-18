use aegis_common::{AgentIdentity, PublicKeyEntry};
use anyhow::{anyhow, Result};

pub fn rotate_key(identity: &mut AgentIdentity, new_key: [u8; 32]) -> Result<()> {

    // deactivate old keys
    for k in identity.keys.iter_mut() {
        k.active = false;
    }

    let new_version = identity.keys.len() as u32 + 1;

    identity.keys.push(PublicKeyEntry {
        key: new_key,
        version: new_version,
        active: true,
    });

    Ok(())
}
