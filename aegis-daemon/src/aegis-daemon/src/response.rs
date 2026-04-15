use crate::isolation;
use aya::maps::HashMap;
use std::sync::Arc;

pub struct ResponseSystem {
    pub blocklist: HashMap<MapData, u32, u32>, // Shared handle to the eBPF map
}

impl ResponseSystem {
    /// The 'Kill-Switch': Executes the fastest possible mitigation for a rogue PID.
    pub async fn trigger_immediate_mitigation(&self, pid: u32, agent_id: &str, ip: Option<u32>) {
        // 1. Kernel-level Network Block (Fastest)
        if let Some(target_ip) = ip {
            let _ = self.blocklist.insert(target_ip, 1, 0);
            println!("[AEGIS-RESPONSE] Kernel Map Updated: IP {} Blocked.", target_ip);
        }

        // 2. Process Termination
        isolation::trigger_kill(agent_id).await;
        
        // 3. Signal to Linux Kernel to drop the PID
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid as i32), 
            nix::sys::signal::Signal::SIGKILL
        );
        
        println!("[AEGIS-RESPONSE] PID {} terminated for Agent {}.", pid, agent_id);
    }
}
