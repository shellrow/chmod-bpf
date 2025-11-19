use anyhow::{Context, Result, anyhow};
use std::process::Command;

/// Runs the provided command and ensures it exits successfully.
pub fn run(command: &mut Command, action: &str) -> Result<()> {
    let status = command
        .status()
        .with_context(|| format!("Failed to {action}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(anyhow!(
            "{action} returned a non-zero exit status: {status}"
        ))
    }
}
