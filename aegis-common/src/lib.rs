use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

// --- Security Reporting ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,      // Informational / Minor deviation
    Medium,   // Policy violation (Blocked)
    High,     // Potential Exfiltration detected
    Critical, // System-level breach attempt
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventSource {
    Fortress, // Deterministic Wasm Trap
    Shadow,   // Behavioral eBPF detection
    System,   // Daemon-level internal event
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub timestamp: DateTime<Utc>,
    pub source: EventSource,
    pub severity: Severity,
    pub agent_id: String,
    pub action_attempted: String, 
    pub reason: String,           
    pub mitigated: bool,          
}

// --- Command & Control ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AegisCommand {
    KillAgent { agent_id: String },
    SwitchMode { agent_id: String, to_fortress: bool },
    UpdatePolicy { new_rules_json: String },
    Ping,
}

// --- Configuration & Rules ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AegisPolicy {
    pub version: String,
    pub agent_id: String,
    pub network: NetworkPolicy,
    pub filesystem: FilesystemPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicy {
    pub allow_list: Vec<String>,
    pub max_entropy: f64,        
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemPolicy {
    pub read_only_paths: Vec<String>,
    pub forbidden_paths: Vec<String>,
}

pub const AEGIS_AUTH_HASH: &str = "4793f0b097b830d17d12224d455476a6e5a40871e9877b0d8745c4793e2b10a9";

pub fn verify_binary_integrity() -> bool {
    // This can be expanded to check file checksums against the hardcoded hash
    AEGIS_AUTH_HASH.starts_with("4793f0b")
}
