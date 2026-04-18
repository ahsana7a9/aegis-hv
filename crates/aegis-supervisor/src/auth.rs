use anyhow::{anyhow, Result};
use aegis_common::{AgentIdentity, Role, AegisCommand};

pub fn authorize(identity: &AgentIdentity, command: &AegisCommand) -> Result<()> {

    match identity.role {

        Role::Admin => Ok(()),

        Role::Supervisor => Ok(()),

        Role::Enforcer => match command {
            AegisCommand::KillProcess(_) => Ok(()),
            AegisCommand::BlockIP(_) => Ok(()),
            _ => Err(anyhow!("Enforcer not allowed for this command")),
        },

        Role::Monitor => Err(anyhow!("Monitor cannot issue commands")),

        Role::ReadOnly => Err(anyhow!("Read-only identity")),

    }
}
