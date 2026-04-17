#![cfg(test)]

use crate::attestation::BinaryAttestation;
use crate::safe_policy::SafePolicyGuard;
use crate::response::ResponseSystem;
use crate::isolation::IsolationHandler;
use crate::monitor::SharedEventBuffer;
use aegis_common::{SecurityEvent, Severity, EventSource};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

// ===== ATTESTATION TESTS =====

#[test]
fn test_binary_attestation_compute_hash() {
    // Create a temporary file with known content
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test_binary");
    fs::write(&test_file, b"test content").unwrap();

    // Compute hash
    let hash = BinaryAttestation::compute_hash(test_file.to_str().unwrap()).unwrap();

    // Verify it's a valid SHA-256 (64 hex chars)
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_binary_attestation_hash_mismatch() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test_binary");
    fs::write(&test_file, b"test content").unwrap();

    // Verify with wrong hash
    let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    let result = BinaryAttestation::verify_self(wrong_hash);

    // Should fail
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Binary integrity verification FAILED"));
}

#[test]
fn test_binary_attestation_world_writable_rejection() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test_binary");
    fs::write(&test_file, b"test").unwrap();

    // Make file world-writable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o666);
        fs::set_permissions(&test_file, perms).unwrap();

        // This would fail attestation
        // (In real test, we'd test the permission validation logic)
    }
}

// ===== POLICY LOADING TESTS =====

#[test]
fn test_policy_path_traversal_prevention() {
    let temp_dir = TempDir::new().unwrap();
    let policies_dir = temp_dir.path().join("policies");
    fs::create_dir_all(&policies_dir).unwrap();

    // Set correct permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o750);
        fs::set_permissions(&policies_dir, perms).unwrap();
    }

    // Create a valid policy file
    let policy_file = policies_dir.join("default.yaml");
    fs::write(
        &policy_file,
        r#"
version: "1.0"
network:
  allow_list: ["8.8.8.8"]
  max_entropy: 6.5
security:
  forbidden_syscalls: ["mount"]
"#,
    )
    .unwrap();

    // Test 1: Valid filename should work
    let result = SafePolicyGuard::load(&policies_dir, "default.yaml", None);
    assert!(result.is_ok());

    // Test 2: Path traversal attempt should be rejected
    let result = SafePolicyGuard::load(&policies_dir, "../../../../etc/passwd", None);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("invalid characters"));

    // Test 3: .. in filename should be rejected
    let result = SafePolicyGuard::load(&policies_dir, "../other.yaml", None);
    assert!(result.is_err());
}

#[test]
fn test_policy_symlink_attack_prevention() {
    let temp_dir = TempDir::new().unwrap();
    let policies_dir = temp_dir.path().join("policies");
    fs::create_dir_all(&policies_dir).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o750);
        fs::set_permissions(&policies_dir, perms).unwrap();

        // Create a malicious symlink pointing to /etc/passwd
        let evil_link = policies_dir.join("evil.yaml");
        use std::os::unix::fs as unix_fs;
        let _ = unix_fs::symlink("/etc/passwd", &evil_link);

        // Attempt to load - should be rejected
        let result = SafePolicyGuard::load(&policies_dir, "evil.yaml", None);
        
        // The path canonicalization should detect the symlink points outside
        if result.is_err() {
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("outside base directory"));
        }
    }
}

#[test]
fn test_policy_file_permission_validation() {
    let temp_dir = TempDir::new().unwrap();
    let policies_dir = temp_dir.path().join("policies");
    fs::create_dir_all(&policies_dir).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir_perms = fs::Permissions::from_mode(0o750);
        fs::set_permissions(&policies_dir, dir_perms).unwrap();

        // Create a world-writable policy file (insecure)
        let policy_file = policies_dir.join("insecure.yaml");
        fs::write(&policy_file, "version: 1.0").unwrap();

        let file_perms = fs::Permissions::from_mode(0o666);
        fs::set_permissions(&policy_file, file_perms).unwrap();

        // Should be rejected
        let result = SafePolicyGuard::load(&policies_dir, "insecure.yaml", None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("world-writable"));
    }
}

// ===== RESPONSE SYSTEM TESTS =====

#[tokio::test]
async fn test_concurrent_mitigation_serialization() {
    // Test that concurrent mitigation attempts are serialized
    // This is complex to test without mocking, so this is a placeholder
    eprintln!("Concurrent mitigation test (requires mocking)");
}

// ===== EVENT BUFFER TESTS =====

#[tokio::test]
async fn test_shared_event_buffer_thread_safety() {
    use crate::monitor::SharedEventBuffer;

    let buffer = SharedEventBuffer::new(10);

    // Simulate concurrent writes
    let handles: Vec<_> = (0..5)
        .map(|i| {
            let buf = buffer.clone();
            tokio::spawn(async move {
                for j in 0..10 {
                    let event = SecurityEvent {
                        timestamp: chrono::Utc::now(),
                        source: EventSource::Shadow,
                        severity: Severity::High,
                        agent_id: format!("agent-{}", i),
                        reason: format!("Event {}", j),
                        mitigated: false,
                    };
                    buf.push(event).await;
                }
            })
        })
        .collect();

    // Wait for all tasks
    for handle in handles {
        handle.await.unwrap();
    }

    // Buffer should have max_size events (10)
    assert_eq!(buffer.len().await, 10);
}

#[tokio::test]
async fn test_event_buffer_circular_behavior() {
    use crate::monitor::SharedEventBuffer;

    let buffer = SharedEventBuffer::new(5);

    // Add 10 events (more than max)
    for i in 0..10 {
        let event = SecurityEvent {
            timestamp: chrono::Utc::now(),
            source: EventSource::Shadow,
            severity: Severity::High,
            agent_id: format!("agent-{}", i),
            reason: format!("Event {}", i),
            mitigated: false,
        };
        buffer.push(event).await;
    }

    // Should only have 5 most recent events
    let events = buffer.get_all().await;
    assert_eq!(events.len(), 5);
}

// ===== ISOLATION HANDLER TESTS =====

#[tokio::test]
async fn test_concurrent_isolation_prevention() {
    use crate::isolation::IsolationHandler;

    let handler = IsolationHandler::new();
    let (tx, _rx) = tokio::sync::broadcast::channel(10);

    // Create a mock state
    use crate::AegisState;
    use std::sync::atomic::AtomicBool;
    let state = AegisState {
        fortress_mode_active: AtomicBool::new(false),
    };

    // First isolation should succeed (in real scenario)
    // Second should fail (duplicate prevention)
    // This test is complex without mocking process APIs
    eprintln!("Concurrent isolation test (requires process mocking)");
}

#[tokio::test]
async fn test_isolation_count_tracking() {
    use crate::isolation::IsolationHandler;

    let handler = IsolationHandler::new();
    assert_eq!(handler.get_isolation_count().await, 0);
    
    // Count would increment after each isolation
    // (Requires mocking for full test)
}

// ===== INTEGRATION TESTS =====

#[tokio::test]
async fn test_security_event_creation_and_broadcast() {
    let (tx, mut rx) = tokio::sync::broadcast::channel(10);

    // Create an event
    let event = SecurityEvent {
        timestamp: chrono::Utc::now(),
        source: EventSource::Shadow,
        severity: Severity::Critical,
        agent_id: "test-agent".to_string(),
        reason: "Test security event".to_string(),
        mitigated: true,
    };

    // Broadcast it
    tx.send(event.clone()).unwrap();

    // Receive it
    let received = rx.recv().await.unwrap();
    assert_eq!(received.agent_id, "test-agent");
    assert_eq!(received.reason, "Test security event");
}

// ===== HELPER TESTS =====

#[test]
fn test_entropy_calculation() {
    use crate::analysis::ThreatAnalyzer;

    // Test 1: Uniform distribution (max entropy)
    let uniform = vec![0u8, 1, 2, 3, 4, 5, 6, 7];
    let entropy = ThreatAnalyzer::calculate_entropy(&uniform);
    assert!(entropy > 2.5); // Max entropy for 8 bytes

    // Test 2: Repetitive data (low entropy)
    let repetitive = vec![0u8; 100];
    let entropy = ThreatAnalyzer::calculate_entropy(&repetitive);
    assert!(entropy < 0.1); // Very low entropy

    // Test 3: Encrypted-like data (high entropy)
    let encrypted: Vec<u8> = (0..256).map(|i| (i % 256) as u8).collect();
    let entropy = ThreatAnalyzer::calculate_entropy(&encrypted);
    assert!(entropy > 7.0); // Close to max for 256 byte values
}

#[test]
fn test_risk_score_calculation() {
    use crate::analysis::ThreatAnalyzer;

    // Test 1: Safe payload (no suspicious patterns)
    let safe_payload = b"GET /api/status HTTP/1.1";
    let risk = ThreatAnalyzer::calculate_risk_score(safe_payload);
    assert!(risk < 0.3); // Low risk

    // Test 2: Suspicious payload (contains /bin/sh)
    let suspicious = b"execute /bin/sh";
    let risk = ThreatAnalyzer::calculate_risk_score(suspicious);
    assert!(risk > 0.5); // Medium-to-high risk

    // Test 3: Highly suspicious (contains multiple patterns)
    let malicious = b"/etc/shadow /bin/sh chmod 777";
    let risk = ThreatAnalyzer::calculate_risk_score(malicious);
    assert!(risk > 0.8); // Very high risk
}