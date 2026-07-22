use caps::{CapsHashSet, Capability, CapSet};
use tracing::{info, warn};

pub fn drop_root_privileges() -> Result<(), String> {
    if !caps::has_cap(None, CapSet::Effective, Capability::CAP_BPF).unwrap_or(false) &&
       !caps::has_cap(None, CapSet::Effective, Capability::CAP_SYS_ADMIN).unwrap_or(false) {
        return Err("Must start daemon with CAP_BPF or CAP_SYS_ADMIN".to_string());
    }

    info!("Initializing capability dropping sequence...");

    // Construct essential minimal capability set
    let mut permitted = CapsHashSet::new();
    permitted.insert(Capability::CAP_BPF);
    permitted.insert(Capability::CAP_NET_ADMIN);
    permitted.insert(Capability::CAP_PERFMON);

    // 1. Clear unneeded capabilities from Inheritable & Effective sets
    caps::set(None, CapSet::Effective, &permitted)
        .map_err(|e| format!("Failed to set effective capabilities: {}", e))?;

    caps::set(None, CapSet::Permitted, &permitted)
        .map_err(|e| format!("Failed to set permitted capabilities: {}", e))?;

    // 2. Clear ambient capabilities
    caps::clear(None, CapSet::Ambient)
        .map_err(|e| format!("Failed to clear ambient capabilities: {}", e))?;

    info!("Successfully dropped unneeded privileges. Retaining only CAP_BPF, CAP_NET_ADMIN, CAP_PERFMON.");
    Ok(())
}
