use crate::{command, permission, resource};
use anyhow::{Result, bail};
use serde::Serialize;
use std::{io, path::Path};

#[derive(Serialize)]
pub struct Status {
    pub label: String,
    pub configuration_present: bool,
    pub registered: bool,
    pub error: Option<String>,
}

pub fn registered(label: &str) -> Result<bool> {
    let output = command::output(
        command::system("/bin/launchctl").args(["print", &format!("system/{label}")]),
        "inspect launchd registration",
    )?;
    match output.status.code() {
        Some(0) => Ok(true),
        // Darwin ESRCH / launchctl's service-not-found code. Do not hide
        // authorization, I/O, or invocation errors as an absent service.
        Some(3 | 113) => Ok(false),
        _ => bail!(
            "Cannot inspect {label}: {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ),
    }
}

pub fn configuration_present(path: &str) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub fn inspect(label: &str, path: &str) -> Status {
    let mut status = Status {
        label: label.into(),
        configuration_present: false,
        registered: false,
        error: None,
    };
    let result = (|| -> Result<()> {
        status.configuration_present = configuration_present(path)?;
        status.registered = registered(label)?;
        if status.configuration_present {
            if label == resource::LABEL {
                permission::validate_asset(Path::new(path))?;
            } else {
                // External package managers may install a root-controlled plist
                // symlink. Resolve it for read-only inspection, never mutation.
                permission::trusted_directory(Path::new("/Library/LaunchDaemons"), false)?;
                let resolved = std::fs::canonicalize(path)?;
                permission::validate_asset(&resolved)?;
            }
        }
        if label == resource::LABEL && status.configuration_present {
            for (path, expected) in [
                (path, resource::CHMOD_BPF_PLIST),
                (resource::CHMOD_BPF_SCRIPT_PATH, resource::CHMOD_BPF_SCRIPT),
            ] {
                permission::verify_installed_asset(Path::new(path), expected.as_bytes())?;
            }
        }
        Ok(())
    })();
    if let Err(error) = result {
        status.error = Some(format!("{error:#}"));
    }
    status
}

pub fn reject_conflicts() -> Result<()> {
    for (label, path) in resource::OTHER_DAEMONS {
        if configuration_present(path)? || registered(label)? {
            bail!(
                "Another BPF manager is installed ({label}). Use that manager, or uninstall it with its original installer before continuing. The shared access_bpf group is preserved."
            );
        }
    }
    Ok(())
}

pub fn unload() -> Result<()> {
    if registered(resource::LABEL)? {
        command::run(
            command::system("/bin/launchctl").args(["bootout", resource::SERVICE]),
            "unload the chmod-bpf daemon",
        )?;
    }
    Ok(())
}

pub fn bootstrap() -> Result<()> {
    command::run(
        command::system("/bin/launchctl").args(["enable", resource::SERVICE]),
        "enable the chmod-bpf daemon",
    )?;
    command::run(
        command::system("/bin/launchctl").args([
            "bootstrap",
            "system",
            resource::CHMOD_BPF_PLIST_PATH,
        ]),
        "register the chmod-bpf daemon",
    )?;
    if !registered(resource::LABEL)? {
        bail!("launchd did not retain the chmod-bpf service registration");
    }
    Ok(())
}
