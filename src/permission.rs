use anyhow::{Context, Result, bail};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Component, Path},
};
use tempfile::NamedTempFile;

// These Darwin ACL functions are not exposed by libc. Types and constants are
// defined by the macOS SDK's sys/acl.h; ACL objects remain owned by libSystem.
unsafe extern "C" {
    fn acl_get_link_np(path: *const libc::c_char, kind: libc::c_int) -> *mut libc::c_void;
    fn acl_get_entry(
        acl: *mut libc::c_void,
        entry_id: libc::c_int,
        entry: *mut *mut libc::c_void,
    ) -> libc::c_int;
    fn acl_free(object: *mut libc::c_void) -> libc::c_int;
}

pub fn has_acl(path: &Path) -> Result<bool> {
    let name = CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: name is NUL-terminated and lives through the call. A non-null
    // result is owned by us and released exactly once after inspecting it.
    let acl = unsafe { acl_get_link_np(name.as_ptr(), 0x100) };
    if acl.is_null() {
        let error = io::Error::last_os_error();
        // Darwin also returns ENOENT when an existing object has no ACL.
        // Recheck existence so a disappeared device is never reported healthy.
        if error.raw_os_error() == Some(libc::ENOENT) {
            fs::symlink_metadata(path)?;
            return Ok(false);
        }
        return Err(error).with_context(|| format!("Cannot inspect ACL on {}", path.display()));
    }
    let mut entry = std::ptr::null_mut();
    // SAFETY: acl is valid and entry is a writable out pointer.
    let result = unsafe { acl_get_entry(acl, 0, &mut entry) };
    let error = io::Error::last_os_error();
    // SAFETY: acl is an owned libSystem allocation, no longer used afterward.
    unsafe { acl_free(acl) };
    if result == 0 {
        Ok(true)
    } else if error.raw_os_error() == Some(libc::EINVAL) {
        Ok(false)
    } else {
        Err(error).context("Cannot inspect the first ACL entry")
    }
}

fn validate_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    owner: u32,
    directory: bool,
) -> Result<()> {
    if metadata.file_type().is_symlink()
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
    {
        bail!(
            "Refusing unexpected file type or symbolic link at {}",
            path.display()
        );
    }
    if metadata.uid() != owner || metadata.mode() & 0o022 != 0 {
        bail!(
            "{} must be owned by UID {owner} and not writable by group or others",
            path.display()
        );
    }
    if !directory && metadata.nlink() != 1 {
        bail!("Refusing multiply linked file at {}", path.display());
    }
    if has_acl(path)? {
        bail!(
            "Refusing ACL-bearing installation path {}; review its ACL manually",
            path.display()
        );
    }
    Ok(())
}

/// Check every existing component before creating, replacing, or removing assets.
/// Non-root users cannot swap components once their ownership and mode are checked.
pub fn trusted_directory(path: &Path, create: bool) -> Result<()> {
    if !path.is_absolute() {
        bail!("Installation directories must be absolute");
    }
    let mut current = std::path::PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir => continue,
            Component::Normal(name) => current.push(name),
            _ => bail!("Installation paths cannot contain traversal components"),
        }
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if !create {
                    return Ok(());
                }
                fs::create_dir(&current)
                    .with_context(|| format!("Cannot create {}", current.display()))?;
                fs::set_permissions(&current, fs::Permissions::from_mode(0o755))?;
                fs::symlink_metadata(&current)?
            }
            Err(error) => return Err(error.into()),
        };
        validate_metadata(&current, &metadata, 0, true)?;
    }
    Ok(())
}

pub fn validate_asset(path: &Path) -> Result<()> {
    trusted_directory(path.parent().context("Asset has no parent")?, false)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_metadata(path, &metadata, 0, false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub struct Snapshot {
    bytes: Vec<u8>,
    mode: u32,
    gid: u32,
}

fn read_snapshot(path: &Path) -> Result<Snapshot> {
    let metadata = fs::symlink_metadata(path)?;
    Ok(Snapshot {
        bytes: fs::read(path)?,
        mode: metadata.mode() & 0o7777,
        gid: metadata.gid(),
    })
}

impl Snapshot {
    fn verify(&self, expected: &[u8]) -> Result<()> {
        if self.mode != 0o644 || self.gid != 0 {
            bail!(
                "Installed asset must have root:wheel ownership and mode 0644; run install to repair"
            );
        }
        if self.bytes != expected {
            bail!("Installed asset differs from this binary; run install to repair or upgrade");
        }
        Ok(())
    }
}

pub fn verify_installed_asset(path: &Path, expected: &[u8]) -> Result<()> {
    let saved = snapshot(path)
        .with_context(|| format!("Cannot inspect {}", path.display()))?
        .with_context(|| format!("Installed asset is missing: {}", path.display()))?;
    saved
        .verify(expected)
        .with_context(|| format!("Cannot verify {}", path.display()))
}

pub fn snapshot(path: &Path) -> Result<Option<Snapshot>> {
    validate_asset(path)?;
    match fs::symlink_metadata(path) {
        Ok(_) => read_snapshot(path).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Replace one file atomically; all ancestors have already been validated.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    validate_asset(path)?;
    replace_owned_file(path, bytes, 0, 0, 0o644)
}

fn replace_owned_file(path: &Path, bytes: &[u8], uid: u32, gid: u32, mode: u32) -> Result<()> {
    let parent = path.parent().context("Asset has no parent")?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    // SAFETY: the descriptor is borrowed from a live File. Ownership is changed
    // on the open temporary inode, never through a potentially replaced path.
    if unsafe { libc::fchown(temporary.as_file().as_raw_fd(), uid, gid) } != 0 {
        return Err(io::Error::last_os_error()).context("Cannot set staged file ownership");
    }
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .with_context(|| format!("Cannot atomically replace {}", path.display()))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

pub fn remove_asset(path: &Path) -> Result<()> {
    validate_asset(path)?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("Cannot remove {}", path.display())),
    }
}

pub fn restore(path: &Path, snapshot: Option<&Snapshot>) -> Result<()> {
    validate_asset(path)?;
    match snapshot {
        Some(snapshot) => replace_owned_file(path, &snapshot.bytes, 0, snapshot.gid, snapshot.mode),
        None => remove_asset(path),
    }
}

/// The lock file is deliberately retained: unlinking it allows concurrent locks
/// on different inodes. Closing the returned file releases the kernel lock.
pub fn administrative_lock() -> Result<File> {
    let path = Path::new(crate::resource::CHMOD_BPF_LOCK_PATH);
    let parent = path.parent().context("Lock has no parent")?;
    trusted_directory(parent, true)?;
    validate_asset(path)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    validate_metadata(path, &file.metadata()?, 0, false)?;
    lock_file(&file)?;
    Ok(file)
}

fn lock_file(file: &File) -> Result<()> {
    // SAFETY: file owns a live descriptor and flock does not retain it.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error()).context(
            "Another chmod-bpf administrative operation may be running; retry after it finishes",
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn rejects_links_writable_files_and_wrong_owners() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asset");
        fs::write(&path, b"safe").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let uid = uzers::get_effective_uid();
        validate_metadata(&path, &fs::symlink_metadata(&path).unwrap(), uid, false).unwrap();
        assert!(
            validate_metadata(&path, &fs::symlink_metadata(&path).unwrap(), uid + 1, false)
                .is_err()
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(
            validate_metadata(&path, &fs::symlink_metadata(&path).unwrap(), uid, false).is_err()
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(
            validate_metadata(&link, &fs::symlink_metadata(&link).unwrap(), uid, false).is_err()
        );
        let hardlink = dir.path().join("hardlink");
        fs::hard_link(&path, hardlink).unwrap();
        assert!(
            validate_metadata(&path, &fs::symlink_metadata(&path).unwrap(), uid, false).is_err()
        );
    }

    #[test]
    fn rejects_extended_acls() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asset");
        fs::write(&path, b"safe").unwrap();
        let status = std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone allow write"])
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(has_acl(&path).unwrap());
        assert!(
            validate_metadata(
                &path,
                &fs::symlink_metadata(&path).unwrap(),
                uzers::get_effective_uid(),
                false
            )
            .is_err()
        );
    }
    #[test]
    fn atomic_replacement_sets_exact_mode_and_leaves_no_staging_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("asset");
        let uid = uzers::get_effective_uid();
        let gid = uzers::get_effective_gid();
        replace_owned_file(&path, b"first", uid, gid, 0o644).unwrap();
        replace_owned_file(&path, b"replacement", uid, gid, 0o644).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o644);
        assert_eq!((metadata.uid(), metadata.gid()), (uid, gid));
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn failed_replacement_keeps_the_destination_and_cleans_staging() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("asset");
        fs::create_dir(&path).unwrap();
        fs::write(path.join("unrelated"), b"keep").unwrap();
        assert!(
            replace_owned_file(
                &path,
                b"replacement",
                uzers::get_effective_uid(),
                uzers::get_effective_gid(),
                0o644
            )
            .is_err()
        );
        assert_eq!(fs::read(path.join("unrelated")).unwrap(), b"keep");
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn kernel_lock_excludes_a_second_open_and_releases_on_drop() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let first = OpenOptions::new()
            .read(true)
            .write(true)
            .open(temporary.path())
            .unwrap();
        let second = OpenOptions::new()
            .read(true)
            .write(true)
            .open(temporary.path())
            .unwrap();
        lock_file(&first).unwrap();
        assert!(lock_file(&second).is_err());
        drop(first);
        lock_file(&second).unwrap();
    }

    #[test]
    fn missing_acl_target_is_an_error() {
        let directory = tempfile::tempdir().unwrap();
        assert!(has_acl(&directory.path().join("missing")).is_err());
    }
    #[test]
    fn administrative_lock_uses_a_trusted_system_parent() {
        // This read-only platform check catches group-writable macOS runtime
        // directories that cannot satisfy the installation trust policy.
        validate_asset(Path::new(crate::resource::CHMOD_BPF_LOCK_PATH)).unwrap();
    }

    #[test]
    fn rejects_group_writable_directories() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o775)).unwrap();
        assert!(
            validate_metadata(
                directory.path(),
                &fs::symlink_metadata(directory.path()).unwrap(),
                uzers::get_effective_uid(),
                true
            )
            .is_err()
        );
    }
    #[test]
    fn snapshots_restore_executable_mode_and_group() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("helper");
        fs::write(&path, b"previous helper").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o750)).unwrap();
        let previous = read_snapshot(&path).unwrap();
        replace_owned_file(
            &path,
            b"new helper",
            uzers::get_effective_uid(),
            uzers::get_effective_gid(),
            0o644,
        )
        .unwrap();
        replace_owned_file(
            &path,
            &previous.bytes,
            uzers::get_effective_uid(),
            previous.gid,
            previous.mode,
        )
        .unwrap();
        let restored = fs::metadata(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"previous helper");
        assert_eq!(restored.mode() & 0o7777, 0o750);
        assert_eq!(restored.gid(), previous.gid);
    }
    #[test]
    fn installed_asset_verification_rejects_metadata_and_content_drift() {
        let mut snapshot = Snapshot {
            bytes: b"expected".to_vec(),
            mode: 0o644,
            gid: 0,
        };
        snapshot.verify(b"expected").unwrap();
        assert!(snapshot.verify(b"different").is_err());
        snapshot.mode = 0o755;
        assert!(snapshot.verify(b"expected").is_err());
        snapshot.mode = 0o644;
        snapshot.gid = 20;
        assert!(snapshot.verify(b"expected").is_err());
    }
}
