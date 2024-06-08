use std::error::Error;
use std::process::Command;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use glob::glob;

pub const BPF_GROUP: &str = "access_bpf";
pub const BPF_GROUP_NAME : &str = "BPF device access ACL";
pub const FORCE_CREATE_BPF_MAX: u32 = 256;

/// Fetches the maximum number of creatable BPF devices on the system.
fn get_max_bpf_devices() -> Result<u32, Box<dyn Error>> {
    // Execute the sysctl command to get the maximum number of BPF devices
    let output = Command::new("sysctl")
        .arg("-n")
        .arg("debug.bpf_maxdevices")
        .output()?;

    if !output.status.success() {
        eprintln!("Failed to execute sysctl command");
        return Err(std::io::Error::from(std::io::ErrorKind::Other).into());
    }

    // Convert the output to a string and parse it as an integer
    let output_str = std::str::from_utf8(&output.stdout)?;
    match output_str.trim().parse::<u32>() {
        Ok(max_devices) => Ok(max_devices),
        Err(_) => {
            eprintln!("Failed to parse the output as an integer");
            Err(std::io::Error::from(std::io::ErrorKind::Other).into())
        },
    }
}

pub fn create_bpf_devices() -> Result<(), Box<dyn Error>> {
    let sysctl_max = get_max_bpf_devices()?;
    let max_devices = std::cmp::min(FORCE_CREATE_BPF_MAX, sysctl_max);
    
    // Iterate and create BPF devices
    for i in 0..max_devices {
        let device_path = format!("/dev/bpf{}", i);
        let _ = Command::new("cat")
            .arg(&device_path)
            .output();
    }

    Ok(())
}

/// Changes the group of the BPF devices to the specified group.
pub fn change_bpf_device_groups(group_name: &str) -> Result<(), Box<dyn Error>> {
    Command::new("chgrp")
        .arg(group_name)
        .arg("/dev/bpf*")
        .status()?;
    Ok(())
}

/// Sets the group read/write permissions for the BPF devices.
pub fn set_bpf_device_permissions() -> Result<(), Box<dyn Error>> {
    Command::new("chmod")
        .arg("g+rw")
        .arg("/dev/bpf*")
        .status()?;
    Ok(())
}

/// Check if the file has group read/write permissions.
pub fn check_read_write_permissions(file_path: &str) -> Result<bool, Box<dyn Error>> {
    let metadata = fs::metadata(Path::new(file_path))?;
    let permissions = metadata.permissions();

    // Extract the mode and shift to check group read/write permissions (rw- --- ---)
    // Group permissions bits are shifted by 3 places to the right.
    const GROUP_READ_WRITE: u32 = 0o0060;
    let has_group_rw = permissions.mode() & GROUP_READ_WRITE == GROUP_READ_WRITE;

    Ok(has_group_rw)
}

/// Check if the current user has read/write permissions for the file.
pub fn check_current_user_read_write_permissions(file_path: &str) -> Result<bool, Box<dyn Error>> {
    let metadata = fs::metadata(Path::new(file_path))?;
    let permissions = metadata.permissions();

    // Extract the mode to check permissions
    let mode = permissions.mode();

    // Check current user's uid and group's gid
    if let Some(user) = crate::user::get_real_current_user() {
        // Check current user's uid
        if user.uid() == metadata.uid() {
            return Ok(mode & 0o600 == 0o600); // Owner read/write
        }
        // Check group's gid
        if let Some(groups) = user.groups() {
            for group in groups {
                if group.gid() == metadata.gid() {
                    return Ok(mode & 0o060 == 0o060); // Group read/write
                }
            }
        }
    }
    // Check others' permissions
    Ok(mode & 0o006 == 0o006) // Others read/write
}

/// Checks if the group has read/write permissions for the BPF devices.
pub fn check_all_bpf_device_permissions() -> Result<(), String> {
    for entry in glob("/dev/bpf*").unwrap().filter_map(Result::ok) {
        let path_str = entry.to_str().unwrap();
        match check_current_user_read_write_permissions(path_str) {
            Ok(has_permissions) => {
                if !has_permissions {
                    return Err(format!("You do not have the read/write permissions for {}.", path_str));
                }
            },
            Err(e) => {
                eprintln!("Failed to check permissions for {}: {}", path_str, e);
                return Err(e.to_string());
            },
        }
    }
    Ok(())
}
