use aegis_common::AegisPolicy;
use sha2::{Sha256, Digest};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use anyhow::{anyhow, Context};

/// Secure policy loader with path canonicalization and validation
/// 
/// Security Features:
/// 1. Path canonicalization (resolves symlinks)
/// 2. Boundary checking (prevents directory traversal)
/// 3. Permission validation (rejects world-writable files)
/// 4. Optional integrity verification (SHA-256 hash check)
pub struct SafePolicyGuard {
    pub active_policy: AegisPolicy,
    policy_path: PathBuf,
}

impl SafePolicyGuard {
    /// Securely loads a policy file with comprehensive validation
    ///
    /// # Arguments
    /// * `base_policy_dir` - Base directory for policies (e.g., /etc/aegis/policies)
    /// * `policy_filename` - Name of the policy file (no path separators allowed)
    /// * `expected_hash` - Optional SHA-256 hash for integrity verification
    ///
    /// # Security Checks
    /// 1. Base directory must exist and be 0700 or 0750
    /// 2. Filename cannot contain path separators (prevents traversal)
    /// 3. Resolved path must stay within base directory
    /// 4. File cannot be world-writable
    /// 5. File hash matches expected (if provided)
    ///
    /// # Example
    /// ```ignore
    /// let policy = SafePolicyGuard::load(
    ///     "/etc/aegis/policies",
    ///     "default.yaml",
    ///     Some("abc123...")
    /// )?;
    /// ```
    pub fn load<P: AsRef<Path>>(
        base_policy_dir: P,
        policy_filename: &str,
        expected_hash: Option<&str>,
    ) -> anyhow::Result<Self> {
        let base = PathBuf::from(base_policy_dir.as_ref());

        // ===== SECURITY CHECK 1: Base Directory Validation =====
        let base_canonical = base.canonicalize()
            .context("Policy directory doesn't exist or is inaccessible")?;

        // Verify directory permissions are restrictive (0700 or 0750)
        #[cfg(unix)]
        {
            let metadata = fs::metadata(&base_canonical)?;
            let perms = metadata.permissions().mode();

            // Check if other users can access the directory (dangerous)
            if (perms & 0o077) != 0 {
                return Err(anyhow!(
                    "❌ SECURITY ERROR: Policy directory has insecure permissions: {:o}\n\
                     Must be 0700 or 0750 (root or root+group only)\n\
                     Fix: sudo chmod 0750 {}",
                    perms,
                    base_canonical.display()
                ));
            }
        }

        // ===== SECURITY CHECK 2: Filename Validation =====
        // Prevent path traversal attacks by rejecting path separators
        if policy_filename.contains('/') || policy_filename.contains("..") {
            return Err(anyhow!(
                "❌ SECURITY ERROR: Policy filename contains invalid characters: {}\n\
                 Filenames must not contain '/' or '..'",
                policy_filename
            ));
        }

        // ===== SECURITY CHECK 3: Path Construction & Canonicalization =====
        let full_path = base_canonical.join(policy_filename);
        let canonical_path = full_path.canonicalize()
            .context("Policy file doesn't exist or is inaccessible")?;

        // ===== SECURITY CHECK 4: Boundary Enforcement =====
        // Verify the canonical path is still within the base directory
        // This prevents symlink attacks like: /etc/aegis/policies/default.yaml -> /etc/passwd
        if !canonical_path.starts_with(&base_canonical) {
            return Err(anyhow!(
                "❌ SECURITY ERROR: Policy file path traversal detected!\n\
                 Resolved path: {}\n\
                 Is outside base directory: {}\n\
                 This is likely a symlink attack. Fix the symlink.",
                canonical_path.display(),
                base_canonical.display()
            ));
        }

        // ===== SECURITY CHECK 5: File Permission Validation =====
        #[cfg(unix)]
        {
            let metadata = fs::metadata(&canonical_path)?;
            let mode = metadata.permissions().mode();

            // File should not be world-readable or world-writable
            if (mode & 0o044) != 0 {
                eprintln!(
                    "⚠️  WARNING: Policy file is world-readable: {:o}",
                    mode
                );
            }

            if (mode & 0o002) != 0 {
                return Err(anyhow!(
                    "❌ SECURITY ERROR: Policy file is world-writable: {:o}\n\
                     Fix: sudo chmod 0640 {}",
                    mode,
                    canonical_path.display()
                ));
            }
        }

        // ===== READ AND PARSE POLICY FILE =====
        let content = fs::read_to_string(&canonical_path)
            .context("Failed to read policy file")?;

        let policy: AegisPolicy = serde_yaml::from_str(&content)
            .context("Failed to parse policy YAML")?;

        // ===== SECURITY CHECK 6: Integrity Verification (Optional) =====
        if let Some(expected) = expected_hash {
            let mut hasher = Sha256::new();
            hasher.update(&content);
            let computed = format!("{:x}", hasher.finalize());

            if computed != expected {
                return Err(anyhow!(
                    "❌ SECURITY ERROR: Policy file integrity check failed!\n\
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

    /// Computes the SHA-256 hash of a policy file
    pub fn compute_hash<P: AsRef<Path>>(policy_path: P) -> anyhow::Result<String> {
        let content = fs::read_to_string(policy_path)?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Returns the canonical path of the loaded policy
    pub fn get_path(&self) -> &Path {
        &self.policy_path
    }

    // --- Policy Evaluation Methods (from original PolicyGuard) ---

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
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_path_traversal_prevention() {
        // Test would require creating temporary policy files
        // This is a placeholder for integration testing
    }

    #[test]
    fn test_symlink_attack_prevention() {
        // Test would verify symlink attacks are blocked
        // Placeholder for integration testing
    }
}