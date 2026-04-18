use anyhow::Result;
use std::fs;
use std::path::Path;

pub fn create_backup(src: &Path, dst: &Path) -> Result<()> {
    fs::copy(src, dst)?;
    Ok(())
}
