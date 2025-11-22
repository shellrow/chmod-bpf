use anyhow::{Result, anyhow};
use std::process::Command;
use std::str;
use tracing::debug;

use crate::command;

pub const KNOWN_DAEMON_PLISTS: [&str; 2] = [
    "/Library/LaunchDaemons/com.foctal.chmod-bpf.plist",
    "/Library/LaunchDaemons/org.wireshark.ChmodBPF.plist",
];

/// Manages the LaunchDaemon by unloading and reloading it.
pub fn reload_daemon(plist_path: &str) -> Result<()> {
    let mut bootout = Command::new("launchctl");
    bootout.arg("bootout").arg("system").arg(plist_path);
    if let Ok(status) = bootout.status() {
        if !status.success() {
            debug!(?status, "launchctl bootout returned a non-zero exit status");
        }
    }

    let mut bootstrap = Command::new("launchctl");
    bootstrap.arg("bootstrap").arg("system").arg(plist_path);
    command::run(&mut bootstrap, "bootstrap the chmod-bpf daemon")
}

/// Unloads the specified LaunchDaemon.
pub fn unload_daemon(plist_path: &str) -> Result<()> {
    let mut command = Command::new("launchctl");
    command.arg("bootout").arg("system").arg(plist_path);
    command::run(&mut command, "unload the chmod-bpf daemon")
}

/// Checks if any of the known daemon settings are present.
pub fn check_known_daemon_settings() -> Result<String> {
    for plist in KNOWN_DAEMON_PLISTS.iter() {
        if std::path::Path::new(plist).exists() {
            return Ok(plist.to_string());
        }
    }
    Err(anyhow!("No known chmod-bpf daemon configuration was found"))
}
