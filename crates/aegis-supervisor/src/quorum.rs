use anyhow::{Result, anyhow};

pub fn require_quorum(success: usize, total: usize) -> Result<()> {
    let needed = (total / 2) + 1;

    if success < needed {
        return Err(anyhow!(
            "Quorum not reached: {} / {} (need {})",
            success, total, needed
        ));
    }

    Ok(())
}
