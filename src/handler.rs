use crate::{MutationOptions, bpf, command, daemon, output, permission, resource, user};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::{
    fs,
    io::{self, IsTerminal, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Serialize)]
struct Audit {
    schema_version: u32,
    checked_at_unix: u64,
    healthy: bool,
    user: Option<String>,
    uid: Option<u32>,
    access_evaluation: &'static str,
    group: &'static str,
    group_gid: Option<u32>,
    directory_member: bool,
    devices: Vec<bpf::Device>,
    daemons: Vec<daemon::Status>,
    issues: Vec<String>,
    hints: Vec<String>,
}

pub fn check(json: bool, target: Option<&str>) -> Result<bool> {
    let mut audit = Audit {
        schema_version: 1,
        checked_at_unix: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        healthy: false,
        user: None,
        uid: None,
        access_evaluation: "unavailable",
        group: bpf::BPF_GROUP,
        group_gid: user::group_gid(),
        directory_member: false,
        devices: Vec::new(),
        daemons: Vec::new(),
        issues: Vec::new(),
        hints: Vec::new(),
    };
    match user::resolve(target) {
        Ok(identity) => {
            audit.user = Some(identity.name.clone());
            audit.uid = Some(identity.uid);
            audit.access_evaluation = if identity.current_process {
                "current_process_access"
            } else {
                "directory_mode_estimate"
            };
            audit.directory_member = audit
                .group_gid
                .is_some_and(|gid| identity.gids.contains(&gid));
            if !audit.directory_member {
                audit
                    .issues
                    .push("The selected account is not a directory member of access_bpf".into());
                audit.hints.push("Grant access only to trusted capture operators using the installed BPF manager".into());
            }
            if !identity.current_process {
                audit.hints.push("This is a mode-bit estimate, not an access check in the selected user's session. Run check without sudo as that user to verify actual OS access".into());
            }
            if identity.uid == 0 {
                audit.hints.push("Root access does not demonstrate that a capture operator can access BPF. Run check without sudo".into());
            }
            match bpf::collect(Path::new("/dev")) {
                Ok(paths) => {
                    audit.devices = paths
                        .iter()
                        .map(|path| bpf::inspect(path, &identity, audit.group_gid))
                        .collect();
                    if audit.devices.is_empty() {
                        audit
                            .issues
                            .push("No numbered BPF devices were found under /dev".into());
                    }
                    let denied = audit
                        .devices
                        .iter()
                        .filter(|d| !d.readable_writable || d.error.is_some())
                        .count();
                    let insecure = audit.devices.iter().filter(|d| !d.secure).count();
                    if denied != 0 {
                        audit.issues.push(format!(
                            "{denied} device(s) are inaccessible or could not be inspected"
                        ));
                        audit.hints.push("After membership changes, log out fully and log back in; existing processes may retain old credentials".into());
                    }
                    if insecure != 0 {
                        audit.issues.push(format!(
                            "{insecure} device(s) do not match root:access_bpf 0660 without ACLs"
                        ));
                    }
                }
                Err(error) => audit.issues.push(format!("{error:#}")),
            }
        }
        Err(error) => audit
            .issues
            .push(format!("Cannot resolve audit account: {error:#}")),
    }
    for (label, path) in std::iter::once((resource::LABEL, resource::CHMOD_BPF_PLIST_PATH))
        .chain(resource::OTHER_DAEMONS)
    {
        let status = daemon::inspect(label, path);
        if let Some(error) = &status.error {
            audit.issues.push(format!("{label}: {error}"));
        }
        if status.configuration_present && !status.registered {
            audit.issues.push(format!(
                "{label} has a configuration file but is not registered with launchd"
            ));
        }
        if status.registered && !status.configuration_present {
            audit.issues.push(format!(
                "{label} is registered but has no configuration for the next boot"
            ));
        }
        audit.daemons.push(status);
    }
    let active = audit.daemons.iter().filter(|d| d.registered).count();
    if active == 0 {
        audit
            .issues
            .push("No known BPF permission daemon is registered with launchd".into());
        audit
            .hints
            .push("Preview installation with chmod-bpf install --dry-run".into());
    } else if active > 1 {
        audit
            .issues
            .push("Multiple BPF managers are registered; keep only one manager installed".into());
    }
    audit.healthy = audit.issues.is_empty();
    if json {
        let mut bytes = serde_json::to_vec_pretty(&audit)?;
        bytes.push(b'\n');
        output::write(&bytes)?;
    } else {
        let accessible = audit.devices.iter().filter(|d| d.readable_writable).count();
        let mut text = format!(
            "BPF audit: {}\nUser: {} (evaluation: {})\nDevices: {accessible}/{} accessible\nGroup: access_bpf; directory membership: {}\n",
            if audit.healthy {
                "healthy"
            } else {
                "attention required"
            },
            audit.user.as_deref().unwrap_or("unresolved"),
            audit.access_evaluation,
            audit.devices.len(),
            if audit.directory_member { "yes" } else { "no" }
        );
        for status in &audit.daemons {
            if status.configuration_present || status.registered {
                text.push_str(&format!(
                    "Daemon: {} ({})\n",
                    status.label,
                    if status.registered {
                        "registered"
                    } else {
                        "not registered"
                    }
                ));
            }
        }
        for issue in &audit.issues {
            text.push_str(&format!("[FAIL] {issue}\n"));
        }
        for device in audit
            .devices
            .iter()
            .filter(|d| !d.secure || !d.readable_writable || d.error.is_some())
            .take(10)
        {
            text.push_str(&format!(
                "  {}: mode={}, uid={:?}, gid={:?}, access={}, secure={}{}\n",
                device.path,
                device.mode.as_deref().unwrap_or("unknown"),
                device.uid,
                device.gid,
                device.readable_writable,
                device.secure,
                device
                    .error
                    .as_ref()
                    .map(|error| format!(", {error}"))
                    .unwrap_or_default()
            ));
        }
        if audit
            .devices
            .iter()
            .filter(|d| !d.secure || !d.readable_writable || d.error.is_some())
            .count()
            > 10
        {
            text.push_str("  Additional device details are available with --json.\n");
        }
        for hint in &audit.hints {
            text.push_str(&format!("Hint: {hint}\n"));
        }
        output::write(text.as_bytes())?;
    }
    Ok(audit.healthy)
}

fn asset_paths() -> [&'static Path; 2] {
    [
        Path::new(resource::CHMOD_BPF_SCRIPT_PATH),
        Path::new(resource::CHMOD_BPF_PLIST_PATH),
    ]
}

fn preflight_assets() -> Result<()> {
    permission::validate_asset(Path::new(resource::CHMOD_BPF_LOCK_PATH))?;
    for path in asset_paths() {
        permission::validate_asset(path)?;
    }
    Ok(())
}

fn approve(options: &MutationOptions) -> Result<bool> {
    if options.dry_run {
        output::write(b"Dry run: no changes made.\n")?;
        return Ok(false);
    }
    user::require_root()?;
    if options.assume_yes {
        return Ok(true);
    }
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        bail!(
            "Interactive confirmation requires a terminal. Review --dry-run, then use --yes for automation."
        );
    }
    eprint!("Apply this plan? [y/N] ");
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        return Ok(true);
    }
    output::write(b"Cancelled; no changes made.\n")?;
    Ok(false)
}

pub fn install(users: Vec<String>, include_admin: bool, options: &MutationOptions) -> Result<()> {
    let users = user::install_users(users, include_admin)?;
    let mut plan = format!(
        "Install/repair plan:\n  Ensure the shared access_bpf group exists.\n  Write root:wheel 0644 assets:\n    {}\n    {}\n  Set BPF devices to root:access_bpf 0660.\n  Enable and register {} (at boot and every 60 seconds).\n",
        resource::CHMOD_BPF_SCRIPT_PATH,
        resource::CHMOD_BPF_PLIST_PATH,
        resource::LABEL
    );
    for name in &users {
        plan.push_str(&format!("  Grant BPF access to {name:?}.\n"));
    }
    if include_admin {
        plan.push_str("  Grant BPF access to every member of admin.\n");
    }
    plan.push_str("Existing memberships, including inherited admin access, are preserved.\nBPF access permits packet capture and raw packet injection.\n");
    output::write(plan.as_bytes())?;
    daemon::reject_conflicts()?;
    preflight_assets()?;
    user::managed_group_gid()?;
    if !approve(options)? {
        return Ok(());
    }
    let _lock = permission::administrative_lock()?;
    daemon::reject_conflicts()?;
    preflight_assets()?;
    permission::trusted_directory(Path::new(resource::CHMOD_BPF_SCRIPT_DIR_PATH), true)?;
    permission::trusted_directory(Path::new("/Library/LaunchDaemons"), true)?;
    let paths = asset_paths();
    let previous = [
        permission::snapshot(paths[0])?,
        permission::snapshot(paths[1])?,
    ];
    let was_registered = daemon::registered(resource::LABEL)?;
    if was_registered && previous.iter().any(Option::is_none) {
        bail!(
            "The registered service has missing assets. Run uninstall first, then install to repair this incomplete state."
        );
    }
    user::ensure_group()?;
    let mut deployment = SystemDeployment { paths, previous };
    crate::installation::deploy(&mut deployment, was_registered)?;
    for name in &users {
        user::change_membership(name, "user", true).context(
            "Daemon installed, but not all memberships were applied; retry install to finish",
        )?;
    }
    if include_admin {
        user::change_membership("admin", "group", true)
            .context("Daemon installed, but admin membership failed; retry install to finish")?;
    }
    output::write(b"Installation completed. Log out fully and log back in, then run chmod-bpf check without sudo.\n")?;
    Ok(())
}

pub fn uninstall(revoke_access: bool, options: &MutationOptions) -> Result<()> {
    let mut plan = format!(
        "Uninstall plan:\n  Unregister {}.\n  Remove only its plist and helper script; preserve unrelated files.\n  Preserve access_bpf and all memberships (the group may be shared).\n",
        resource::LABEL
    );
    plan.push_str(if revoke_access {
        "  Reset all numbered BPF devices to root:wheel 0600 without ACLs.\n  Existing open capture handles are not revoked.\n"
    } else {
        "  Preserve current device permissions; they may remain until reboot.\n"
    });
    output::write(plan.as_bytes())?;
    preflight_assets()?;
    if revoke_access {
        daemon::reject_conflicts()?;
    }
    if !approve(options)? {
        return Ok(());
    }
    let _lock = permission::administrative_lock()?;
    preflight_assets()?;
    if revoke_access {
        daemon::reject_conflicts()?;
    }
    daemon::unload()?;
    if revoke_access {
        bpf::revoke_devices()?;
    }
    // Remove the boot-time entry first so an interrupted cleanup cannot leave
    // a plist that references a helper we have already deleted.
    for path in asset_paths().into_iter().rev() {
        permission::remove_asset(path)?;
    }
    match fs::remove_dir(resource::CHMOD_BPF_SCRIPT_DIR_PATH) {
        Ok(()) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
            ) => {}
        Err(error) => {
            return Err(error)
                .context("Assets removed, but the helper directory could not be removed");
        }
    }
    output::write(b"Uninstallation completed. Shared group memberships were preserved.\n")?;
    Ok(())
}

pub fn membership(users: Vec<String>, grant: bool, options: &MutationOptions) -> Result<()> {
    let users = user::validate_users(users)?;
    if user::managed_group_gid()?.is_none() {
        bail!("access_bpf does not exist. Install a BPF manager first.");
    }
    permission::validate_asset(Path::new(resource::CHMOD_BPF_LOCK_PATH))?;
    let mut plan = format!(
        "{} direct access_bpf membership for: {}\n",
        if grant { "Grant" } else { "Revoke" },
        users.join(", ")
    );
    plan.push_str(if grant {
        "This permits packet capture and raw packet injection.\n"
    } else {
        "Inherited memberships and already-open capture handles are unaffected.\n"
    });
    output::write(plan.as_bytes())?;
    if !approve(options)? {
        return Ok(());
    }
    let _lock = permission::administrative_lock()?;
    user::managed_group_gid()?.context("access_bpf disappeared before the membership update")?;
    for name in users {
        user::change_membership(&name, "user", grant)
            .context("Membership update failed; earlier accounts may already be updated")?;
    }
    output::write(b"Memberships updated. Affected users must log out fully and log back in.\n")?;
    Ok(())
}

struct SystemDeployment {
    paths: [&'static Path; 2],
    previous: [Option<permission::Snapshot>; 2],
}

impl crate::installation::Deployment for SystemDeployment {
    fn stop(&mut self) -> Result<()> {
        daemon::unload()
    }

    fn stage_and_apply(&mut self) -> Result<()> {
        permission::atomic_write(self.paths[0], resource::CHMOD_BPF_SCRIPT.as_bytes())?;
        permission::atomic_write(self.paths[1], resource::CHMOD_BPF_PLIST.as_bytes())?;
        command::run(
            command::system("/usr/bin/plutil")
                .arg("-lint")
                .arg(self.paths[1]),
            "validate the launch daemon plist",
        )?;
        // A registered job may not have run yet. Synchronous execution makes
        // permission-update failures visible before we grant memberships.
        command::run(
            command::system("/bin/sh").arg(self.paths[0]),
            "apply BPF permissions",
        )
    }

    fn start(&mut self) -> Result<()> {
        daemon::bootstrap()
    }

    fn restore_assets(&mut self) -> Result<()> {
        let mut errors = Vec::new();
        for (path, bytes) in self.paths.iter().zip(&self.previous) {
            if let Err(error) = permission::restore(path, bytes.as_ref()) {
                errors.push(format!("{error:#}"));
            }
        }
        if !errors.is_empty() {
            bail!("{}", errors.join("; "));
        }
        Ok(())
    }
}
