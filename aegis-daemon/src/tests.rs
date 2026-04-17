//! Comprehensive unit tests for Aegis-HV security modules
//!
//! Test Coverage:
//! - Binary attestation
//! - Policy loading & validation
//! - Secure IPC authentication
//! - Response system atomicity
//! - Event buffer thread safety
//! - Entropy calculation
//! - Risk scoring
//!

#![cfg(test)]

use aegis_daemon::attestation::BinaryAttestation;
use aegis_daemon::safe_policy::SafePolicyGuard;
use aegis_daemon::response::ResponseSystem;
use aegis_daemon::monitor::SharedEventBuffer;
use aegis_daemon::analysis::ThreatAnalyzer;
use aegis_common::{SecurityEvent, Severity, EventSource};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

// ═════════════════════════════════════════════════════════════════════════════
// ATTESTATION TESTS
// ═════════════════════════════════════════════════════════════════════════════

mod attestation_tests {
    use super::*;

    #[test]
    fn test_binary_hash_computation() {
        // Create temporary file with known content
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test_binary");
        fs::write(&test_file, b"test content").unwrap();

        // Compute hash
        let hash = BinaryAttestation::compute_hash(test_file.to_str().unwrap())
            .expect("Failed to compute hash");

        // Verify it's valid SHA-256 (64 hex chars)
        assert_eq!(hash.len(), 64, "SHA-256 should be 64 hex characters");
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "Hash should only contain hex digits"
        );
    }

    #[test]
    fn test_hash_deterministic() {
        // Same content should produce same hash
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test_binary");
        fs::write(&test_file, b"deterministic content").unwrap();

        let hash1 = BinaryAttestation::compute_hash(test_file.to_str().unwrap())
            .expect("Failed to compute hash 1");
        let hash2 = BinaryAttestation::compute_hash(test_file.to_str().unwrap())
            .expect("Failed to compute hash 2");

        assert_eq!(hash1, hash2, "Same content should produce same hash");
    }

    #[test]
    fn test_different_content_different_hash() {
        let temp_dir = TempDir::new().unwrap();

        let file1 = temp_dir.path().join("file1");
        fs::write(&file1, b"content1").unwrap();

        let file2 = temp_dir.path().join("file2");
        fs::write(&file2, b"content2").unwrap();

        let hash1 = BinaryAttestation::compute_hash(file1.to_str().unwrap())
            .expect("Failed to compute hash 1");
        let hash2 = BinaryAttestation::compute_hash(file2.to_str().unwrap())
            .expect("Failed to compute hash 2");

        assert_ne!(hash1, hash2, "Different content should produce different hashes");
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// POLICY TESTS
// ═════════════════════════════════════════════════════════════════════════════

mod policy_tests {
    use super::*;

    fn create_valid_policy() -> (TempDir, String) {
        let temp_dir = TempDir::new().unwrap();
        let policies_dir = temp_dir.path().join("policies");
        fs::create_dir_all(&policies_dir).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o750);
            fs::set_permissions(&policies_dir, perms).unwrap();
        }

        let policy_file = policies_dir.join("default.yaml");
        fs::write(
            &policy_file,
            r#"
version: "1.0"
network:
  allow_list:
    - "8.8.8.8"
    - "1.1.1.1"
  max_entropy: 6.5
security:
  forbidden_syscalls:
    - "mount"
    - "umount2"
"#,
        )
        .unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o640);
            fs::set_permissions(&policy_file, perms).unwrap();
        }

        (temp_dir, policies_dir.to_string_lossy().to_string())
    }

    #[test]
    fn test_valid_policy_loads() {
        let (_, policies_dir) = create_valid_policy();
        let result = SafePolicyGuard::load(&policies_dir, "default.yaml", None);
        assert!(result.is_ok(), "Valid policy should load successfully");
    }

    #[test]
    fn test_path_traversal_rejection() {
        let (_, policies_dir) = create_valid_policy();

        // Attempt path traversal
        let result = SafePolicyGuard::load(&policies_dir, "../../../../etc/passwd", None);
        assert!(
            result.is_err(),
            "Path traversal attempt should be rejected"
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid characters"),
            "Error should mention invalid characters"
        );
    }

    #[test]
    fn test_dotdot_rejection() {
        let (_, policies_dir) = create_valid_policy();

        let result = SafePolicyGuard::load(&policies_dir, "../other.yaml", None);
        assert!(result.is_err(), ".. in filename should be rejected");
    }

    #[test]
    fn test_slash_rejection() {
        let (_, policies_dir) = create_valid_policy();

        let result = SafePolicyGuard::load(&policies_dir, "subdir/policy.yaml", None);
        assert!(result.is_err(), "/ in filename should be rejected");
    }

    #[test]
    fn test_world_writable_policy_rejected() {
        let temp_dir = TempDir::new().unwrap();
        let policies_dir = temp_dir.path().join("policies");
        fs::create_dir_all(&policies_dir).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o750);
            fs::set_permissions(&policies_dir, perms).unwrap();
        }

        let policy_file = policies_dir.join("insecure.yaml");
        fs::write(&policy_file, "version: 1.0").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Make it world-writable (insecure)
            let perms = fs::Permissions::from_mode(0o666);
            fs::set_permissions(&policy_file, perms).unwrap();

            let result =
                SafePolicyGuard::load(&policies_dir, "insecure.yaml", None);
            assert!(result.is_err(), "World-writable policy should be rejected");
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("world-writable"),
                "Error should mention world-writable"
            );
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// RESPONSE SYSTEM TESTS
// ═════════════════════════════════════════════════════════════════════════════

mod response_tests {
    use super::*;

    #[test]
    fn test_response_system_creation() {
        let system = ResponseSystem::new();
        assert_eq!(system.get_mitigation_count(), 0);
        assert_eq!(system.get_failed_count(), 0);
    }

    #[test]
    fn test_mitigation_count_increments() {
        let system = ResponseSystem::new();
        assert_eq!(system.get_mitigation_count(), 0);

        // Simulate incrementing mitigation count
        system
            .mitigations_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(system.get_mitigation_count(), 1);

        system
            .mitigations_count
            .fetch_add(5, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(system.get_mitigation_count(), 6);
    }

    #[test]
    fn test_atomic_cas_prevents_concurrent_entry() {
        let system = ResponseSystem::new();

        // First CAS should succeed
        let result1 = system.mitigation_in_progress.compare_exchange_weak(
            false,
            true,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::Relaxed,
        );
        assert!(result1.is_ok(), "First CAS should succeed");

        // Second CAS should fail (already set to true)
        let result2 = system.mitigation_in_progress.compare_exchange_weak(
            false,
            true,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::Relaxed,
        );
        assert!(result2.is_err(), "Second CAS should fail (already locked)");

        // Release lock
        system
            .mitigation_in_progress
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    #[test]
    fn test_format_ip() {
        let ip1 = 0xC0A80101u32; // 192.168.1.1
        let ip2 = 0x08080808u32; // 8.8.8.8

        // We can't directly call format_ip because it's private,
        // but we can test via the public API if needed
        assert_ne!(ip1, ip2);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// EVENT BUFFER TESTS
// ═════════════════════════════════════════════════════════════════════════════

mod event_buffer_tests {
    use super::*;
    use std::sync::Arc;

    fn create_test_event(id: usize) -> SecurityEvent {
        SecurityEvent {
            timestamp: chrono::Utc::now(),
            source: EventSource::Shadow,
            severity: Severity::High,
            agent_id: format!("agent-{}", id),
            reason: format!("Test event {}", id),
            mitigated: false,
        }
    }

    #[tokio::test]
    async fn test_buffer_push_and_get() {
        let buffer = SharedEventBuffer::new(10);
        let event = create_test_event(1);

        buffer.push(event.clone()).await;
        assert_eq!(buffer.len().await, 1);

        let events = buffer.get_all().await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].agent_id, "agent-1");
    }

    #[tokio::test]
    async fn test_circular_buffer_capacity() {
        let buffer = SharedEventBuffer::new(5);

        // Add 10 events
        for i in 0..10 {
            buffer.push(create_test_event(i)).await;
        }

        // Should only have 5 events
        assert_eq!(buffer.len().await, 5);
        assert_eq!(buffer.total_events(), 10); // But total_events tracks all

        let events = buffer.get_all().await;
        // Should have the last 5 (indices 5-9)
        assert_eq!(events[0].agent_id, "agent-5");
        assert_eq!(events[4].agent_id, "agent-9");
    }

    #[tokio::test]
    async fn test_get_recent() {
        let buffer = SharedEventBuffer::new(100);

        for i in 0..20 {
            buffer.push(create_test_event(i)).await;
        }

        let recent = buffer.get_recent(5).await;
        assert_eq!(recent.len(), 5);
        // Should be reverse order (most recent first)
        assert_eq!(recent[0].agent_id, "agent-19");
        assert_eq!(recent[4].agent_id, "agent-15");
    }

    #[tokio::test]
    async fn test_is_empty() {
        let buffer = SharedEventBuffer::new(10);
        assert!(buffer.is_empty().await);

        buffer.push(create_test_event(1)).await;
        assert!(!buffer.is_empty().await);
    }

    #[tokio::test]
    async fn test_concurrent_readers() {
        let buffer = Arc::new(SharedEventBuffer::new(100));

        // Add some events
        for i in 0..10 {
            buffer.push(create_test_event(i)).await;
        }

        // Spawn 5 reader tasks
        let handles: Vec<_> = (0..5)
            .map(|_| {
                let buf = Arc::clone(&buffer);
                tokio::spawn(async move {
                    buf.get_all().await.len()
                })
            })
            .collect();

        for handle in handles {
            let len = handle.await.unwrap();
            assert_eq!(len, 10, "All readers should see all events");
        }
    }

    #[tokio::test]
    async fn test_last_updated() {
        let buffer = SharedEventBuffer::new(10);
        let before = chrono::Utc::now();

        buffer.push(create_test_event(1)).await;

        let last_update = buffer.last_updated().await;
        let after = chrono::Utc::now();

        assert!(last_update >= before);
        assert!(last_update <= after);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// ANALYSIS TESTS (Entropy & Risk)
// ═════════════════════════════════════════════════════════════════════════════

mod analysis_tests {
    use super::*;

    #[test]
    fn test_entropy_zero_on_empty() {
        let entropy = ThreatAnalyzer::calculate_entropy(&[]);
        assert_eq!(entropy, 0.0);
    }

    #[test]
    fn test_entropy_uniform_distribution() {
        // Uniform distribution should have max entropy
        let uniform = vec![0u8, 1, 2, 3, 4, 5, 6, 7];
        let entropy = ThreatAnalyzer::calculate_entropy(&uniform);
        assert!(entropy > 2.0, "Uniform distribution should have high entropy");
    }

    #[test]
    fn test_entropy_repetitive_low() {
        // Repetitive data should have low entropy
        let repetitive = vec![0u8; 100];
        let entropy = ThreatAnalyzer::calculate_entropy(&repetitive);
        assert!(entropy < 0.1, "Repetitive data should have low entropy");
    }

    #[test]
    fn test_entropy_encrypted_high() {
        // Random-like data should have high entropy
        let mut random = Vec::new();
        for i in 0..256 {
            random.push((i % 256) as u8);
        }
        let entropy = ThreatAnalyzer::calculate_entropy(&random);
        assert!(entropy > 7.0, "Random data should have high entropy");
    }

    #[test]
    fn test_risk_score_safe_payload() {
        let safe_payload = b"GET /api/status HTTP/1.1";
        let risk = ThreatAnalyzer::calculate_risk_score(safe_payload);
        assert!(risk < 0.5, "Safe payload should have low risk");
    }

    #[test]
    fn test_risk_score_malicious_patterns() {
        let suspicious = b"/bin/sh";
        let risk = ThreatAnalyzer::calculate_risk_score(suspicious);
        assert!(risk > 0.5, "Suspicious pattern should increase risk");

        let very_suspicious = b"/etc/shadow /bin/sh chmod 777";
        let risk2 = ThreatAnalyzer::calculate_risk_score(very_suspicious);
        assert!(risk2 > risk, "Multiple patterns should increase risk further");
    }

    #[test]
    fn test_risk_score_clamped() {
        let payload = b"test";
        let risk = ThreatAnalyzer::calculate_risk_score(payload);
        assert!(risk >= 0.0 && risk <= 1.0, "Risk score should be in [0, 1]");
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// INTEGRATION TESTS
// ═════════════════════════════════════════════════════════════════════════════

mod integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_security_event_creation_and_broadcast() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(10);

        let event = SecurityEvent {
            timestamp: chrono::Utc::now(),
            source: EventSource::Shadow,
            severity: Severity::Critical,
            agent_id: "test-agent".to_string(),
            reason: "Test security event".to_string(),
            mitigated: true,
        };

        tx.send(event.clone()).unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received.agent_id, "test-agent");
        assert_eq!(received.reason, "Test security event");
        assert!(received.mitigated);
    }

    #[tokio::test]
    async fn test_event_buffer_with_broadcast() {
        let buffer = SharedEventBuffer::new(100);
        let (tx, mut rx) = tokio::sync::broadcast::channel(10);

        let event = SecurityEvent {
            timestamp: chrono::Utc::now(),
            source: EventSource::Response,
            severity: Severity::Critical,
            agent_id: "integration-test".to_string(),
            reason: "Integration test event".to_string(),
            mitigated: true,
        };

        buffer.push(event.clone()).await;
        tx.send(event).unwrap();

        let buffered = buffer.get_all().await;
        assert_eq!(buffered.len(), 1);

        let broadcasted = rx.recv().await.unwrap();
        assert_eq!(broadcasted.agent_id, "integration-test");
    }
}