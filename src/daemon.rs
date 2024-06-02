use std::error::Error;
use std::process::{Command, Stdio};
use std::str;

pub const KNOWN_DAEMON_LABELS: [&str; 1] = ["org.wireshark.ChmodBPF"];
pub const KNOWN_DAEMON_PLISTS: [&str; 1] = ["/Library/LaunchDaemons/org.wireshark.ChmodBPF.plist"];

/// Checks if the specified LaunchDaemon is loaded.
pub fn is_daemon_loaded(label: &str) -> Result<bool, Box<dyn Error>> {
    let output = Command::new("launchctl")
        .arg("list")
        .stdout(Stdio::piped())
        .output()?;

    if !output.status.success() {
        // Handle the error properly in real scenarios
        eprintln!("Command execution failed");
        return Err(std::io::Error::from(std::io::ErrorKind::Other).into());
    }
    println!("{}", str::from_utf8(&output.stdout)?);
    // Convert output to string and search for the label
    let output_str = str::from_utf8(&output.stdout)?;
    Ok(output_str.contains(label))
}

/// Manages the LaunchDaemon by unloading and reloading it.
pub fn reload_daemon(plist_path: &str) -> std::io::Result<()> {
    // Unload the daemon if it's already loaded
    Command::new("launchctl")
        .arg("bootout")
        .arg("system")
        .arg(plist_path)
        .output()?;

    // Load the daemon
    let status = Command::new("launchctl")
        .arg("bootstrap")
        .arg("system")
        .arg(plist_path)
        .status()?;

    if status.success() {
        println!("Daemon reloaded successfully.");
    } else {
        eprintln!("Failed to reload daemon.");
    }

    Ok(())
}

/// Checks if any of the known daemon settings are present.
pub fn known_daemon_setting_exists() -> bool {
    for plist in KNOWN_DAEMON_PLISTS.iter() {
        if std::path::Path::new(plist).exists() {
            return true;
        }
    }
    false
}

/// Checks if any of the known daemons are loaded.
pub fn known_daemons_loaded() -> bool {
    for label in KNOWN_DAEMON_LABELS.iter() {
        match is_daemon_loaded(label) {
            Ok(loaded) => {
                if loaded {
                    return true;
                }
            },
            Err(e) => eprintln!("Failed to check daemon {}: {}", label, e),
        }
    }
    false
}
