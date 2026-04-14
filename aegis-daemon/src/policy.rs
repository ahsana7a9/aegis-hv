use aegis_common::{AegisPolicy, Severity};
use std::fs;

pub struct PolicyGuard {
    pub active_policy: AegisPolicy,
}

impl PolicyGuard {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path)?;
        let policy: AegisPolicy = serde_yaml::from_str(&content)?;
        Ok(Self { active_policy: policy })
    }

    /// Checks if a network destination is allowed
    pub fn check_network(&self, destination: &str) -> bool {
        self.active_policy.network.allow_list.contains(&destination.to_string())
    }

    /// Checks if an entropy score is within limits
    pub fn is_entropy_safe(&self, score: f64) -> bool {
        score <= self.active_policy.network.max_entropy
    }
}
