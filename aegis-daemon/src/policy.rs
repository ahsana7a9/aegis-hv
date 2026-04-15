use aegis_common::AegisPolicy;
use std::fs;
use std::path::Path;
use anyhow::Context;

pub struct PolicyGuard {
    pub active_policy: AegisPolicy,
}

impl PolicyGuard {
    /// Loads and parses the YAML policy from a given path.
    /// Returns an error if the file is missing or the schema is invalid.
    pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let content = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read policy file at {:?}", path.as_ref()))?;
        
        // Parse the YAML into our shared AegisPolicy struct
        let policy: AegisPolicy = serde_yaml::from_str(&content)
            .context("Failed to deserialize AegisPolicy YAML")?;
        
        Ok(Self { active_policy: policy })
    }

    /// Determines if a network destination is explicitly permitted.
    /// This is used by the Daemon to decide whether to update the eBPF BLOCKLIST.
    pub fn check_network(&self, destination: &str) -> bool {
        self.active_policy.network.allow_list
            .iter()
            .any(|allowed| allowed == destination)
    }

    /// Evaluates if an entropy score exceeds the threshold defined in the policy.
    /// Higher entropy often indicates encrypted data exfiltration attempts.
    pub fn is_entropy_safe(&self, score: f64) -> bool {
        score <= self.active_policy.network.max_entropy
    }

    /// Validates if a specific system call is permitted for the current agent role.
    pub fn is_syscall_allowed(&self, syscall_name: &str) -> bool {
        // Zero-Trust: If it's in the forbidden list, it's a hard NO.
        !self.active_policy.security.forbidden_syscalls
            .iter()
            .any(|forbidden| forbidden == syscall_name)
    }
}
