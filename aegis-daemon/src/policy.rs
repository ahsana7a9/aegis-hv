use aegis_common::AegisPolicy;
use sha2::{Sha256, Digest};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use anyhow::{anyhow, Context};

/// Secure policy loader with path canonicalization and validation
pub struct SafePolicyGuard {
    pub active_policy: AegisPolicy,
    policy_path: PathBuf,
}

impl SafePolicyGuard {
    pub fn load<P: AsRef<Path>>(
        base_policy_dir: P,
        policy_filename: &str,
        expected_hash: Option<&str>,
    ) -> anyhow::Result<Self> {
        let base = PathBuf::from(base_policy_dir.as_ref());

        let base_canonical = base.canonicalize()
            .context("Policy directory doesn't exist or is inaccessible")?;

        #[cfg(unix)]
        {
            let metadata = fs::metadata(&base_canonical)?;
            let perms = metadata.permissions().mode();

            if (perms & 0o077) != 0 {
                return Err(anyhow!(
                    " SECURITY ERROR: Policy directory has insecure permissions: {:o}\n\
                     Must be 0700 or 0750 (root or root+group only)\n\
                     Fix: sudo chmod 0750 {}",
                    perms,
                    base_canonical.display()
                ));
            }
        }

        if policy_filename.contains('/') || policy_filename.contains("..") {
            return Err(anyhow!(
                " SECURITY ERROR: Policy filename contains invalid characters: {}\n\
                 Filenames must not contain '/' or '..'",
                policy_filename
            ));
        }

        let full_path = base_canonical.join(policy_filename);
        let canonical_path = full_path.canonicalize()
            .context("Policy file doesn't exist or is inaccessible")?;

        if !canonical_path.starts_with(&base_canonical) {
            return Err(anyhow!(
                " SECURITY ERROR: Policy file path traversal detected!\n\
                 Resolved path: {}\n\
                 Is outside base directory: {}\n\
                 This is likely a symlink attack. Fix the symlink.",
                canonical_path.display(),
                base_canonical.display()
            ));
        }

        #[cfg(unix)]
        {
            let metadata = fs::metadata(&canonical_path)?;
            let mode = metadata.permissions().mode();

            if (mode & 0o044) != 0 {
                eprintln!(
                    "  WARNING: Policy file is world-readable: {:o}",
                    mode
                );
            }

            if (mode & 0o002) != 0 {
                return Err(anyhow!(
                    " SECURITY ERROR: Policy file is world-writable: {:o}\n\
                     Fix: sudo chmod 0640 {}",
                    mode,
                    canonical_path.display()
                ));
            }
        }

        let content = fs::read_to_string(&canonical_path)
            .context("Failed to read policy file")?;

        let policy: AegisPolicy = serde_yaml::from_str(&content)
            .context("Failed to parse policy YAML")?;

        if let Some(expected) = expected_hash {
            let mut hasher = Sha256::new();
            hasher.update(&content);
            let computed = format!("{:x}", hasher.finalize());

            if computed != expected {
                return Err(anyhow!(
                    " SECURITY ERROR: Policy file integrity check failed!\n\
                     Expected hash: {}\n\
                     Computed hash: {}\n\
                     The policy file has been modified.",
                    expected,
                    computed
                ));
            }
        }

        println!(
            "[AEGIS-POLICY] ✓ Policy loaded securely from: {}",
            canonical_path.display()
        );

        Ok(Self {
            active_policy: policy,
            policy_path: canonical_path,
        })
    }

    pub fn compute_hash<P: AsRef<Path>>(policy_path: P) -> anyhow::Result<String> {
        let content = fs::read_to_string(policy_path)?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        Ok(format!("{:x}", hasher.finalize()))
    }

    pub fn get_path(&self) -> &Path {
        &self.policy_path
    }

    pub fn check_network(&self, destination: &str) -> bool {
        self.active_policy.network.allow_list
            .iter()
            .any(|allowed| allowed == destination)
    }

    pub fn is_entropy_safe(&self, score: f64) -> bool {
        score <= self.active_policy.network.max_entropy
    }

    pub fn is_syscall_allowed(&self, syscall_name: &str) -> bool {
        !self.active_policy.security.forbidden_syscalls
            .iter()
            .any(|forbidden| forbidden == syscall_name)
    }
}

// Backward compatibility alias
pub use SafePolicyGuard as PolicyGuard;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_traversal_prevention() {
        // Tests would require temporary policy files
    }
}