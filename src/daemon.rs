use std::error::Error;
use std::process::{Command, Stdio};
use std::str;

pub const KNOWN_DAEMON_LABELS: [&str; 2] =
    ["com.fortnium.chmod-bpf.plist", "org.wireshark.ChmodBPF"];
pub const KNOWN_DAEMON_PLISTS: [&str; 2] = [
    "/Library/LaunchDaemons/com.fortnium.chmod-bpf.plist",
    "/Library/LaunchDaemons/org.wireshark.ChmodBPF.plist",
];

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

/// Unloads the specified LaunchDaemon.
pub fn unload_daemon(plist_path: &str) -> std::io::Result<()> {
    Command::new("launchctl")
        .arg("bootout")
        .arg("system")
        .arg(plist_path)
        .output()?;
    Ok(())
}

/// Checks if any of the known daemon settings are present.
pub fn check_known_daemon_settings() -> Result<String, Box<dyn Error>> {
    for plist in KNOWN_DAEMON_PLISTS.iter() {
        if std::path::Path::new(plist).exists() {
            return Ok(plist.to_string());
        }
    }
    Err(std::io::Error::from(std::io::ErrorKind::NotFound).into())
}

/// Checks if any of the known daemons are loaded.
pub fn check_known_daemons() -> Result<String, Box<dyn Error>> {
    for label in KNOWN_DAEMON_LABELS.iter() {
        match is_daemon_loaded(label) {
            Ok(loaded) => {
                if loaded {
                    return Ok(label.to_string());
                }
            }
            Err(e) => eprintln!("Failed to check daemon {}: {}", label, e),
        }
    }
    Err(std::io::Error::from(std::io::ErrorKind::NotFound).into())
}
