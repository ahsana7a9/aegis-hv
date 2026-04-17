// --- Core Security & Analysis Modules ---
pub mod analysis;      // Shannon Entropy and behavioral risk scoring
pub mod attestation;   // ✅ NEW: Binary integrity verification
pub mod monitor;       // eBPF event ingestion and telemetry processing
pub mod response;      // Mitigation logic and threat reaction

// --- Infrastructure & Persistence ---
pub mod db;            // SQLite forensic logging and audit trails
pub mod errors;        // ✅ NEW: Standardized error definitions (AegisError)
pub mod policy;        // Base policy structures
pub mod safe_policy;   // ✅ NEW: Hardened policy loader with path traversal prevention

// --- Communication & Control ---
pub mod ipc;           // Legacy/Internal IPC structures
pub mod secure_ipc;    // ✅ NEW: Root-only UDS with SO_PEERCRED verification

// --- Enforcement & Sandboxing ---
pub mod enforcement;   // Kernel-level enforcement logic
pub mod isolation;     // Process termination and resource isolation
pub mod sandbox;       // ✅ NEW: Wasmtime orchestration and VM management

// --- Testing ---
#[cfg(test)]
mod tests;             // ✅ NEW: Unit tests for core security modules

// --- Global Re-exports ---
pub use attestation::BinaryAttestation;
pub use errors::{AegisError, AegisResult};
pub use isolation::IsolationHandler;
pub use monitor::SharedEventBuffer;
pub use response::ResponseSystem;
pub use safe_policy::SafePolicyGuard;
pub use secure_ipc::SecureIpcServer;

/// The current version of the Aegis-HV Security Kernel
pub const VERSION: &str = "1.0.1-Security-Genesis";

/// Global initialization flag for the security state
pub static SHIELD_ACTIVE: std::sync::atomic::AtomicBool = 
    std::sync::atomic::AtomicBool::new(false);
