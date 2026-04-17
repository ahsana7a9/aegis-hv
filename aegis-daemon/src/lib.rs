pub mod analysis;
pub mod attestation;       // ✅ NEW
pub mod db;
pub mod enforcement;
pub mod isolation;
pub mod ipc;
pub mod monitor;
pub mod policy;
pub mod safe_policy;       // ✅ NEW
pub mod secure_ipc;        // ✅ NEW
pub mod response;

// Re-export commonly used types
pub use attestation::BinaryAttestation;
pub use secure_ipc::SecureIpcServer;
pub use safe_policy::SafePolicyGuard;