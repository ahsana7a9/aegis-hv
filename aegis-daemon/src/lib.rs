// --- Core Security & Analysis Modules ---
pub mod analysis;      // Shannon Entropy and behavioral risk scoring
pub mod attestation;   // ✅ NEW: Binary SHA-256 self-verification logic
pub mod monitor;       // eBPF event ingestion and telemetry processing
pub mod response;      // Mitigation logic and threat reaction

// --- Infrastructure & Persistence ---
pub mod db;            // SQLite forensic logging and audit trails
pub mod policy;        // Base policy structures
pub mod safe_policy;   // ✅ NEW: Hardened policy loader with path canonicalization

// --- Communication & Control ---
pub mod ipc;           // Legacy/Internal IPC structures
pub mod secure_ipc;    // ✅ NEW: Root-only UDS with SO_PEERCRED verification

// --- Enforcement Layers ---
pub mod enforcement;   // Kernel-level enforcement logic
pub mod isolation;     // Wasmtime sandboxing and process termination

// --- Global Re-exports ---
// These allow main.rs and external crates to access hardened guards directly
pub use attestation::BinaryAttestation;
pub use secure_ipc::SecureIpcServer;
pub use safe_policy::SafePolicyGuard;

/// The current version of the Aegis-HV Security Kernel
pub const VERSION: &str = "1.0.1-Security-Genesis";

/// Global initialization flag for the security state
pub static SHIELD_ACTIVE: std::sync::atomic::AtomicBool = 
    std::sync::atomic::AtomicBool::new(false);
