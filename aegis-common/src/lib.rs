use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

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
    pub action_attempted: String, // e.g., "sys_write to /etc/passwd"
    pub reason: String,           // e.g., "Entropy threshold exceeded"
    pub mitigated: bool,          // Was the action successfully blocked?
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AegisCommand {
    KillAgent { agent_id: String },
    SwitchMode { agent_id: String, to_fortress: bool },
    UpdatePolicy { new_rules_json: String },
    Ping,
}
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AegisPolicy {
    pub version: String,
    pub agent_id: String,
    pub network: NetworkPolicy,
    pub filesystem: FilesystemPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicy {
    pub allow_list: Vec<String>, // List of IPs or Domains
    pub max_entropy: f64,        // Threshold for exfiltration alerts
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemPolicy {
    pub read_only_paths: Vec<String>,
    pub forbidden_paths: Vec<String>,
}
