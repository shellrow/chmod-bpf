use anyhow::{Context, Result, anyhow};
use std::env;
use std::process::Command;
use std::str;
use uzers::{User, get_current_username, get_effective_uid, get_group_by_name, get_user_by_name};

use crate::command;

pub const MIN_GID: u32 = 100;

/// Check if the group exists.
pub fn group_exists(group_name: &str) -> bool {
    get_group_by_name(group_name).is_some()
}

pub fn get_original_user() -> Option<String> {
    env::var("SUDO_USER").ok()
}

pub fn require_root() -> Result<()> {
    if get_effective_uid() == 0 {
        Ok(())
    } else {
        Err(anyhow!(
            "This command must be executed with elevated privileges (sudo)."
        ))
    }
}

pub fn get_real_current_user() -> Option<User> {
    if let Some(user_name) = get_original_user() {
        get_user_by_name(&user_name)
    } else if let Some(user_name) = get_current_username() {
        get_user_by_name(&user_name)
    } else {
        None
    }
}

/// Creates a new group with the specified name and GID.
pub fn create_group(group_name: &str, group_real_name: &str, gid: u32) -> Result<()> {
    let mut command = Command::new("dseditgroup");
    command
        .arg("-q")
        .arg("-o")
        .arg("create")
        .arg("-i")
        .arg(gid.to_string())
        .arg("-r")
        .arg(group_real_name)
        .arg(group_name);

    command::run(
        &mut command,
        &format!("create group {group_name} with gid {gid}"),
    )
}

/// Get the first available GID starting from min_gid.
pub fn get_free_gid(min_gid: u32) -> Result<u32> {
    let output = Command::new("dscl")
        .arg(".")
        .arg("-list")
        .arg("/Groups")
        .arg("PrimaryGroupID")
        .output()
        .context("Failed to query dscl for group IDs")?;

    if !output.status.success() {
        return Err(anyhow!(
            "dscl exited with status {} while searching for a free gid",
            output.status
        ));
    }

    let output_str = str::from_utf8(&output.stdout).context("dscl output was not UTF-8")?;
    let mut gids: Vec<u32> = output_str
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .filter_map(|gid| gid.parse::<u32>().ok())
        .collect::<Vec<u32>>();
    gids.sort_unstable();

    let mut current_gid = min_gid;
    for gid in gids {
        if gid != current_gid && gid >= min_gid {
            break;
        }
        current_gid += 1;
    }

    Ok(current_gid)
}

/// Adds the current user to the specified group.
pub fn add_current_user_to_group(group_name: &str) -> Result<()> {
    let user =
        get_real_current_user().ok_or_else(|| anyhow!("Unable to resolve the current user"))?;
    let username = user.name().to_string_lossy().into_owned();

    let mut command = Command::new("dseditgroup");
    command
        .arg("-q")
        .arg("-o")
        .arg("edit")
        .arg("-a")
        .arg(&username)
        .arg("-t")
        .arg("user")
        .arg(group_name);
    command::run(
        &mut command,
        &format!("add user {username} to group {group_name}"),
    )
}

/// Check if the current user is in the specified group.
pub fn current_user_in_group(group_name: &str) -> bool {
    if let Some(user_name) = get_current_username() {
        if let Some(user) = get_user_by_name(&user_name) {
            if let Some(groups) = user.groups() {
                for group in groups {
                    if group.name() == group_name {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Adds the specified group to the specified group.
pub fn add_group_to_group(group: &str, target_group: &str) -> Result<()> {
    let mut command = Command::new("dseditgroup");
    command
        .arg("-q")
        .arg("-o")
        .arg("edit")
        .arg("-a")
        .arg(group)
        .arg("-t")
        .arg("group")
        .arg(target_group);
    command::run(
        &mut command,
        &format!("add group {group} to group {target_group}"),
    )
}

/// Deletes the specified group.
pub fn delete_group(group_name: &str) -> Result<()> {
    let mut command = Command::new("dseditgroup");
    command.arg("-o").arg("delete").arg(group_name);
    command::run(&mut command, &format!("delete group {group_name}"))
}
