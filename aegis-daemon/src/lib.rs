pub mod analysis;
pub mod attestation;       //  NEW - Add this line
pub mod db;
pub mod enforcement;
pub mod isolation;
pub mod ipc;
pub mod monitor;
pub mod policy;
pub mod safe_policy;       //  NEW - Add this line
pub mod secure_ipc;        //  NEW - Add this line
pub mod response;

// Re-export commonly used types
pub use attestation::BinaryAttestation;
pub use secure_ipc::SecureIpcServer;
pub use safe_policy::SafePolicyGuard;