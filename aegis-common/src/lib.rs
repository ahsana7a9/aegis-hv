use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

// --- Security Reporting ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventSource {
    Fortress,
    Shadow,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub timestamp: DateTime<Utc>,
    pub source: EventSource,
    pub severity: Severity,
    pub agent_id: Uuid,
    pub action_attempted: String,
    pub reason: String,
    pub mitigated: bool,
}

// --- Command & Control ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AegisCommand {
    KillAgent { agent_id: Uuid },
    SwitchMode { agent_id: Uuid, to_fortress: bool },
    UpdatePolicy { new_rules_json: String },
    Ping,
}

// --- Configuration & Rules ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AegisPolicy {
    pub version: String,
    pub agent_id: Uuid,
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
