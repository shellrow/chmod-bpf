use crate::{command, permission, user::Identity};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::{
    ffi::CString,
    fs, io,
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt},
    },
    path::{Path, PathBuf},
};

pub const BPF_GROUP: &str = "access_bpf";

#[derive(Serialize)]
pub struct Device {
    pub path: String,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub mode: Option<String>,
    pub readable_writable: bool,
    pub secure: bool,
    pub error: Option<String>,
}

fn is_bpf_name(name: &str) -> bool {
    name.strip_prefix("bpf")
        .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()))
}

pub fn collect(directory: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in
        fs::read_dir(directory).with_context(|| format!("Cannot scan {}", directory.display()))?
    {
        let entry = entry?;
        if entry.file_name().to_str().is_some_and(is_bpf_name) {
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
}

fn mode_allows_rw(mode: u32, owner: u32, group: u32, identity: &Identity) -> bool {
    if identity.uid == 0 {
        return true;
    }
    let mask = if identity.uid == owner {
        0o600
    } else if identity.gids.contains(&group) {
        0o060
    } else {
        0o006
    };
    mode & mask == mask
}

pub fn inspect(path: &Path, identity: &Identity, expected_gid: Option<u32>) -> Device {
    let mut device = Device {
        path: path.display().to_string(),
        uid: None,
        gid: None,
        mode: None,
        readable_writable: false,
        secure: false,
        error: None,
    };
    let result = (|| -> Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_char_device() {
            bail!("Expected a BPF character device; refusing a regular file or symbolic link");
        }
        device.uid = Some(metadata.uid());
        device.gid = Some(metadata.gid());
        device.mode = Some(format!("{:04o}", metadata.mode() & 0o7777));
        let has_acl = permission::has_acl(path)?;
        device.secure = metadata.uid() == 0
            && Some(metadata.gid()) == expected_gid
            && metadata.mode() & 0o7777 == 0o660
            && !has_acl;
        device.readable_writable = if identity.current_process {
            let name = CString::new(path.as_os_str().as_bytes())?;
            // SAFETY: name is a valid NUL-terminated string. access checks the
            // real account's OS permissions without opening or consuming a BPF node.
            if unsafe { libc::access(name.as_ptr(), libc::R_OK | libc::W_OK) } == 0 {
                true
            } else {
                let error = io::Error::last_os_error();
                if matches!(error.raw_os_error(), Some(libc::EACCES | libc::EPERM)) {
                    false
                } else {
                    return Err(error.into());
                }
            }
        } else {
            if has_acl {
                bail!(
                    "Cannot estimate another account's access to an ACL-bearing device; run check as that account"
                );
            }
            mode_allows_rw(metadata.mode(), metadata.uid(), metadata.gid(), identity)
        };
        Ok(())
    })();
    if let Err(error) = result {
        device.error = Some(format!("{error:#}"));
    }
    device
}

pub fn revoke_devices() -> Result<()> {
    revoke_paths(&collect(Path::new("/dev"))?, command::run)
}

fn revoke_paths(
    paths: &[PathBuf],
    mut run: impl FnMut(&mut std::process::Command, &str) -> Result<()>,
) -> Result<()> {
    // Inspect the entire set before changing anything. Small batches avoid both
    // hundreds of subprocesses and the system argument-length limit.
    for path in paths {
        if !fs::symlink_metadata(path)?.file_type().is_char_device() {
            bail!("Refusing unexpected device type at {}", path.display());
        }
        if permission::has_acl(path)? {
            bail!(
                "Refusing an unexpected ACL on BPF device {}",
                path.display()
            );
        }
    }
    for batch in paths.chunks(128) {
        run(
            command::system("/bin/chmod").arg("0600").args(batch),
            "revoke BPF device access",
        )?;
        run(
            command::system("/usr/sbin/chown")
                .arg("root:wheel")
                .args(batch),
            "restore BPF device ownership",
        )?;
        // devfs does not support extended ACLs; chmod -N would fail even
        // though the preflight above has confirmed that no ACL is present.
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_only_numbered_bpf_devices() {
        for name in ["bpf0", "bpf123", "bpf00"] {
            assert!(is_bpf_name(name));
        }
        for name in ["bpf", "bpf0.old", "bpfhelper", "bpf-1", "bpf１２", "abpf0"] {
            assert!(!is_bpf_name(name));
        }
    }

    #[test]
    fn permissions_obey_owner_group_other_precedence() {
        let mut identity = Identity {
            name: "test".into(),
            uid: 501,
            gids: vec![20, 101],
            current_process: false,
        };
        assert!(mode_allows_rw(0o660, 0, 101, &identity));
        assert!(!mode_allows_rw(0o606, 0, 101, &identity));
        assert!(!mode_allows_rw(0o066, 501, 101, &identity));
        assert!(mode_allows_rw(0o606, 0, 999, &identity));
        assert!(!mode_allows_rw(0o640, 0, 101, &identity));
        identity.uid = 0;
        assert!(mode_allows_rw(0o000, 0, 101, &identity));
    }

    #[test]
    fn device_audit_rejects_regular_files_and_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("bpf0");
        fs::write(&file, b"not a device").unwrap();
        let identity = Identity {
            name: "test".into(),
            uid: 501,
            gids: vec![20],
            current_process: false,
        };
        assert!(inspect(&file, &identity, Some(101)).error.is_some());
        let link = dir.path().join("bpf1");
        std::os::unix::fs::symlink("/dev/null", &link).unwrap();
        assert!(inspect(&link, &identity, Some(101)).error.is_some());
        fs::write(dir.path().join("bpf.conf"), b"").unwrap();
        assert_eq!(collect(dir.path()).unwrap().len(), 2);
    }
    #[test]
    fn revocation_validates_every_node_before_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let invalid = directory.path().join("bpf1");
        fs::write(&invalid, b"not a device").unwrap();
        let mut calls = 0;
        assert!(
            revoke_paths(&[PathBuf::from("/dev/null"), invalid], |_, _| {
                calls += 1;
                Ok(())
            })
            .is_err()
        );
        assert_eq!(calls, 0);
    }

    #[test]
    fn revocation_batches_commands_and_stops_after_failure() {
        let paths = vec![PathBuf::from("/dev/null"); 129];
        let mut commands = Vec::new();
        revoke_paths(&paths, |command, _| {
            if command.get_args().any(|argument| argument == "-N") {
                bail!("devfs does not support ACL removal");
            }
            commands.push(command.get_args().count());
            Ok(())
        })
        .unwrap();
        assert_eq!(commands, [129, 129, 2, 2]);
        let mut calls = 0;
        assert!(
            revoke_paths(&paths, |_, _| {
                calls += 1;
                bail!("injected command failure")
            })
            .is_err()
        );
        assert_eq!(calls, 1);
    }
}
