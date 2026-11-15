use anyhow::{Context, Result, bail};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
};
use uzers::{
    User, get_current_uid, get_effective_uid, get_group_by_name, get_user_by_name, get_user_by_uid,
};

use crate::{bpf::BPF_GROUP, command};

pub const MIN_GID: u32 = 100;

pub struct Identity {
    pub name: String,
    pub uid: u32,
    pub gids: Vec<u32>,
    pub current_process: bool,
}

pub fn require_root() -> Result<()> {
    if get_effective_uid() != 0 {
        bail!("This operation requires root. Re-run with sudo, or use --dry-run to preview it.");
    }
    Ok(())
}

fn account(name: &str) -> Result<User> {
    if name.is_empty()
        || name.starts_with('-')
        || name.chars().any(|c| c.is_control() || c == '/' || c == ':')
    {
        bail!("Invalid account name: {name:?}");
    }
    get_user_by_name(name).with_context(|| format!("Account {name:?} does not exist"))
}

pub fn resolve(name: Option<&str>) -> Result<Identity> {
    let user = if let Some(name) = name {
        account(name)?
    } else if get_effective_uid() == 0 && env::var_os("SUDO_USER").is_some() {
        let name = env::var("SUDO_USER").context("SUDO_USER is not valid UTF-8; use --user")?;
        let user = account(&name)?;
        let uid: u32 = env::var("SUDO_UID")
            .context("SUDO_UID is missing; use --user")?
            .parse()
            .context("Invalid SUDO_UID; use --user")?;
        if uid != user.uid() {
            bail!("SUDO_USER and SUDO_UID disagree; specify --user explicitly");
        }
        user
    } else {
        get_user_by_uid(get_current_uid()).context("Unable to resolve the current account")?
    };
    let groups = user
        .groups()
        .context("Unable to resolve account group memberships")?;
    let mut gids: Vec<_> = groups.iter().map(|group| group.gid()).collect();
    gids.push(user.primary_group_id());
    gids.sort_unstable();
    gids.dedup();
    Ok(Identity {
        name: user
            .name()
            .to_str()
            .context("Account name is not valid UTF-8")?
            .to_owned(),
        uid: user.uid(),
        gids,
        current_process: user.uid() == get_current_uid() && user.uid() == get_effective_uid(),
    })
}

pub fn install_users(mut users: Vec<String>, include_admin: bool) -> Result<Vec<String>> {
    if users.is_empty() && !include_admin {
        users.push(resolve(None)?.name);
    }
    validate_users(users)
}

pub fn validate_users(users: Vec<String>) -> Result<Vec<String>> {
    let mut names = BTreeSet::new();
    for name in users {
        let user = account(&name)?;
        if user.uid() == 0 {
            bail!("Root already has BPF access. Specify a non-root account with --user.");
        }
        names.insert(
            user.name()
                .to_str()
                .context("Account name is not valid UTF-8")?
                .to_owned(),
        );
    }
    Ok(names.into_iter().collect())
}

pub fn group_gid() -> Option<u32> {
    get_group_by_name(BPF_GROUP).map(|group| group.gid())
}

fn local_groups() -> Result<BTreeMap<String, u32>> {
    let output = command::output(
        command::system("/usr/bin/dscl").args([".", "-list", "/Groups", "PrimaryGroupID"]),
        "list local group IDs",
    )?;
    if !output.status.success() {
        bail!(
            "Unable to list local groups: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    parse_groups(std::str::from_utf8(&output.stdout).context("Invalid dscl output")?)
}

fn validate_group_resolution(local: Option<u32>, resolved: Option<u32>) -> Result<Option<u32>> {
    if local != resolved {
        bail!(
            "access_bpf must resolve to the same local group through Directory Services. Resolve any network-group shadowing or stale directory cache before changing access."
        );
    }
    Ok(local)
}

/// Mutations target the local node; never use a network-only or shadowed group.
pub fn managed_group_gid() -> Result<Option<u32>> {
    validate_group_resolution(local_groups()?.get(BPF_GROUP).copied(), group_gid())
}

pub fn ensure_group() -> Result<()> {
    let groups = local_groups()?;
    if validate_group_resolution(groups.get(BPF_GROUP).copied(), group_gid())?.is_some() {
        return Ok(());
    }
    let gids = groups.values().copied().collect();
    let gid = first_free_gid(&gids, MIN_GID, |gid| uzers::get_group_by_gid(gid).is_some())?;
    command::run(
        command::system("/usr/sbin/dseditgroup").args([
            "-q",
            "-n",
            ".",
            "-o",
            "create",
            "-i",
            &gid.to_string(),
            "-r",
            "BPF device access",
            BPF_GROUP,
        ]),
        "create access_bpf",
    )?;
    if managed_group_gid()? != Some(gid) {
        bail!(
            "The new access_bpf group is not yet resolvable; retry installation after Directory Services refreshes"
        );
    }
    Ok(())
}

fn parse_groups(text: &str) -> Result<BTreeMap<String, u32>> {
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let (name, value) = line
                .trim_end()
                .rsplit_once(char::is_whitespace)
                .context("Malformed dscl group record")?;
            if name.trim().is_empty() {
                bail!("Missing group name in dscl output");
            }
            // macOS includes the signed nobody/nogroup ID (-2).
            let gid: i64 = value.parse().context("Invalid group ID in dscl output")?;
            if !(-2_147_483_648..=4_294_967_295).contains(&gid) {
                bail!("Group ID is out of range");
            }
            Ok((name.trim_end().to_owned(), gid as u32))
        })
        .collect()
}

fn first_free_gid(
    gids: &BTreeSet<u32>,
    minimum: u32,
    mut resolves: impl FnMut(u32) -> bool,
) -> Result<u32> {
    let mut candidate = minimum;
    while gids.contains(&candidate) || resolves(candidate) {
        candidate = candidate
            .checked_add(1)
            .context("No group IDs are available")?;
    }
    Ok(candidate)
}

pub fn change_membership(name: &str, kind: &str, grant: bool) -> Result<()> {
    command::run(
        command::system("/usr/sbin/dseditgroup").args([
            "-q",
            "-n",
            ".",
            "-o",
            "edit",
            if grant { "-a" } else { "-d" },
            name,
            "-t",
            kind,
            BPF_GROUP,
        ]),
        &format!(
            "{} {kind} {name:?} {} access_bpf",
            if grant { "add" } else { "remove" },
            if grant { "to" } else { "from" }
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gid_allocation_ignores_lower_and_duplicate_ids() {
        let groups =
            parse_groups("wheel 0\nstaff 20\na 100\nb 100\nc 102 \t\nnobody -2\n").unwrap();
        let gids = groups.values().copied().collect();
        assert_eq!(first_free_gid(&gids, 100, |_| false).unwrap(), 101);
        assert_eq!(
            first_free_gid(&BTreeSet::new(), 100, |_| false).unwrap(),
            100
        );
        assert!(first_free_gid(&BTreeSet::from([u32::MAX]), u32::MAX, |_| false).is_err());
    }

    #[test]
    fn malformed_group_records_fail_closed() {
        for input in ["group", "group invalid", "group 4294967296"] {
            assert!(parse_groups(input).is_err());
        }
    }

    #[test]
    fn invalid_accounts_are_rejected() {
        for name in ["", "-root", "a/b", "a\nb", "a:b"] {
            assert!(account(name).is_err());
        }
    }
    #[test]
    fn gid_allocation_checks_local_and_network_ids_together() {
        assert_eq!(
            first_free_gid(&BTreeSet::from([101]), 100, |gid| gid == 100).unwrap(),
            102
        );
    }

    #[test]
    fn mutations_reject_network_only_or_shadowed_groups() {
        assert_eq!(validate_group_resolution(None, None).unwrap(), None);
        assert_eq!(
            validate_group_resolution(Some(101), Some(101)).unwrap(),
            Some(101)
        );
        for (local, resolved) in [(None, Some(101)), (Some(101), None), (Some(101), Some(102))] {
            assert!(validate_group_resolution(local, resolved).is_err());
        }
    }
}
