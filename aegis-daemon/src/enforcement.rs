pub struct EnforcementLayer {
    blocklist: HashMap<u32, u32>, // Handle to the eBPF map
}

impl EnforcementLayer {
    /// Actively blocks a malicious IP at the kernel level
    pub fn block_ip(&self, ip: u32) -> anyhow::Result<()> {
        // This writes directly to the eBPF map, enabling instant hardware-level defense
        self.blocklist.insert(ip, 1)?; 
        println!("[AEGIS-ENFORCE] Active Defense: IP {} blocked in kernel.", ip);
        Ok(())
    }

    /// Kills a process that has attempted a boundary breach
    pub fn terminate_agent(&self, pid: u32) {
        use nix::sys::signal::{self, Signal};
        use nix::unistd::Pid;

        let _ = signal::kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
        println!("[AEGIS-ENFORCE] Active Defense: PID {} terminated.", pid);
    }
}
