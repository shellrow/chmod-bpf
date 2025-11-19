use anyhow::{Context, Result, bail};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const BPF_GROUP: &str = "access_bpf";
pub const BPF_GROUP_NAME: &str = "BPF Device ACL";

fn collect_bpf_device_paths() -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in fs::read_dir("/dev").context("Failed to scan /dev for BPF devices")? {
        let entry = entry?;
        let file_name = entry.file_name();
        if file_name.to_string_lossy().starts_with("bpf") {
            paths.push(entry.path());
        }
    }
    Ok(paths)
}

/// Check if the current user has read/write permissions for the file.
pub fn check_current_user_read_write_permissions(file_path: &str) -> Result<bool> {
    let metadata = fs::metadata(Path::new(file_path))
        .with_context(|| format!("Failed to read metadata for {file_path}"))?;
    let permissions = metadata.permissions();

    let mode = permissions.mode();
    if let Some(user) = crate::user::get_real_current_user() {
        if user.uid() == metadata.uid() {
            return Ok(mode & 0o600 == 0o600);
        }
        if let Some(groups) = user.groups() {
            for group in groups {
                if group.gid() == metadata.gid() {
                    return Ok(mode & 0o060 == 0o060);
                }
            }
        }
    }
    Ok(mode & 0o006 == 0o006)
}

/// Checks if the group has read/write permissions for the BPF devices.
pub fn check_all_bpf_device_permissions() -> Result<()> {
    let devices = collect_bpf_device_paths()?;
    if devices.is_empty() {
        bail!("No BPF device nodes were found under /dev");
    }

    for entry in devices {
        let path_str = entry.to_string_lossy();
        let has_permissions = check_current_user_read_write_permissions(&path_str)
            .with_context(|| format!("Failed to evaluate permissions for {path_str}"))?;
        if !has_permissions {
            bail!("Missing read/write permissions for {path_str}");
        }
    }
    Ok(())
}
