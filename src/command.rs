use anyhow::{Context, Result, bail};
use std::process::{Command, Output, Stdio};

/// Use only absolute system paths and a predictable environment for privileged tools.
pub fn system(program: &str) -> Command {
    assert!(program.starts_with('/'));
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LC_ALL", "C")
        .env("HOME", "/var/root")
        .stdin(Stdio::null());
    command
}

pub fn output(command: &mut Command, action: &str) -> Result<Output> {
    command
        .output()
        .with_context(|| format!("Failed to {action}"))
}

pub fn run(command: &mut Command, action: &str) -> Result<()> {
    let output = output(command, action)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let detail = if stderr.trim().is_empty() {
            stdout.trim()
        } else {
            stderr.trim()
        };
        bail!("Failed to {action} ({}): {detail}", output.status);
    }
    Ok(())
}
