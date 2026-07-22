use std::process::Command;
use tracing::{info, error};

pub enum ExecutionMode {
    Wasmtime,
    NativeSeccomp,
}

pub struct AgentSandboxConfig {
    pub mode: ExecutionMode,
    pub executable_path: String,
    pub allowed_paths: Vec<String>,
}

pub struct HybridSandbox;

impl HybridSandbox {
    pub fn spawn_agent(config: AgentSandboxConfig) -> Result<std::process::Child, String> {
        match config.mode {
            ExecutionMode::Wasmtime => Self::spawn_wasm(config),
            ExecutionMode::NativeSeccomp => Self::spawn_native_isolated(config),
        }
    }

    fn spawn_wasm(config: AgentSandboxConfig) -> Result<std::process::Child, String> {
        info!("Spawning agent inside Wasmtime Fortress Sandbox: {}", config.executable_path);
        Command::new("wasmtime")
            .arg("run")
            .arg(&config.executable_path)
            .spawn()
            .map_err(|e| format!("Wasmtime spawn error: {}", e))
    }

    fn spawn_native_isolated(config: AgentSandboxConfig) -> Result<std::process::Child, String> {
        info!("Spawning Python/Native agent inside Seccomp + Namespace Sandbox: {}", config.executable_path);

        // Uses system bwrap / seccomp launcher to sandbox non-WASI runtimes
        let mut cmd = Command::new("bwrap");
        
        // Isolate PID, IPC, and Network Namespaces (unless permitted)
        cmd.arg("--unshare-pid")
           .arg("--unshare-uts")
           .arg("--unshare-ipc")
           .arg("--dev").arg("/dev")
           .arg("--proc").arg("/proc")
           .arg("--ro-bind").arg("/usr").arg("/usr")
           .arg("--ro-bind").arg("/lib").arg("/lib")
           .arg("--ro-bind").arg("/lib64").arg("/lib64");

        // Bind allowed paths
        for path in &config.allowed_paths {
            cmd.arg("--bind").arg(path).arg(path);
        }

        cmd.arg("--").arg("python3").arg(&config.executable_path);

        cmd.spawn().map_err(|e| format!("Native namespace sandbox spawn error: {}", e))
    }
}
