use std::env;
use std::error::Error;
use std::process::Command;
use std::str;
use uzers::{get_current_username, get_group_by_name, get_user_by_name};

pub const MIN_GID: u32 = 100;

/// Check if the user exists.
pub fn user_exists(user_name: &str) -> bool {
    get_user_by_name(user_name).is_some()
}

/// Check if the group exists.
pub fn group_exists(group_name: &str) -> bool {
    get_group_by_name(group_name).is_some()
}

pub fn get_original_user() -> Option<String> {
    env::var("SUDO_USER").ok()
}

pub fn get_original_uid() -> Option<u32> {
    env::var("SUDO_UID").ok().and_then(|uid| uid.parse().ok())
}

/// Creates a new group with the specified name and GID.
pub fn create_group(
    group_name: &str,
    group_real_name: &str,
    gid: u32,
) -> Result<(), Box<dyn Error>> {
    Command::new("dseditgroup")
        .arg("-q")
        .arg("-o")
        .arg("create")
        .arg("-i")
        .arg(gid.to_string())
        .arg("-r")
        .arg(group_real_name)
        .arg(group_name)
        .status()?;

    println!(
        "Group '{}' with GID {} and name '{}' created successfully.",
        group_name, gid, group_real_name
    );
    Ok(())
}

/// Get the first available GID starting from min_gid.
pub fn get_free_gid(min_gid: u32) -> Result<u32, Box<dyn Error>> {
    // Execute the dscl command to list groups and their GIDs
    let output = Command::new("dscl")
        .arg(".")
        .arg("-list")
        .arg("/Groups")
        .arg("PrimaryGroupID")
        .output()?;

    if !output.status.success() {
        eprintln!("Command execution failed");
        return Err(std::io::Error::from(std::io::ErrorKind::Other).into());
    }

    // Parse the output and collect GIDs
    let output_str = str::from_utf8(&output.stdout)?;
    let mut gids: Vec<u32> = output_str
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .filter_map(|gid| gid.parse::<u32>().ok())
        .collect();

    // Sort GIDs
    gids.sort_unstable();

    // Find the first available GID starting from min_gid
    let mut current_gid = min_gid;
    for gid in gids {
        if gid != current_gid && gid >= min_gid {
            break;
        }
        current_gid += 1;
    }

    Ok(current_gid)
}

pub fn get_real_current_user() -> Option<uzers::User> {
    if let Some(user_name) = get_original_user() {
        get_user_by_name(&user_name)
    } else {
        if let Some(user_name) = get_current_username() {
            get_user_by_name(&user_name)
        } else {
            None
        }
    }
}

/// Adds the current user to the specified group.
pub fn add_current_user_to_group(group_name: &str) -> Result<(), Box<dyn Error>> {
    let user: uzers::User = if let Some(user_name) = get_original_user() {
        if let Some(user) = get_user_by_name(&user_name) {
            user
        } else {
            return Err("Original user not found".into());
        }
    } else {
        if let Some(user_name) = get_current_username() {
            if let Some(user) = get_user_by_name(&user_name) {
                user
            } else {
                return Err("Current user not found".into());
            }
        } else {
            return Err("Current user not found".into());
        }
    };
    log::info!(
        "Adding user '{}' to group '{}'",
        user.name().to_string_lossy(),
        group_name
    );
    Command::new("dseditgroup")
        .arg("-q") // Quiet mode, suppresses some output
        .arg("-o")
        .arg("edit")
        .arg("-a")
        .arg(user.name().to_string_lossy().as_ref())
        .arg("-t")
        .arg("user")
        .arg(group_name)
        .status()?;
    Ok(())
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

/// Check if the specified user is in the specified group.
pub fn user_in_group(user_name: &str, group_name: &str) -> bool {
    // Retrieve the user by name
    let user = match get_user_by_name(user_name) {
        Some(user) => user,
        None => return false, // User not found
    };
    match user.groups() {
        Some(groups) => {
            //println!("Groups: {:?}", groups);
            for group in groups {
                if group.name() == group_name {
                    return true;
                }
            }
        }
        None => return false,
    }
    false
}

/// Adds the specified user to the specified group.
pub fn add_user_to_group(user: &str, group: &str) -> Result<(), Box<dyn Error>> {
    Command::new("dseditgroup")
        .arg("-q") // Quiet mode, suppresses some output
        .arg("-o")
        .arg("edit")
        .arg("-a")
        .arg(user) // The name of the user to add
        .arg("-t")
        .arg("user") // The type of the entity to add, which is a user
        .arg(group) // The target group
        .status()?;
    Ok(())
}

/// Adds the specified group to the specified group.
pub fn add_group_to_group(group: &str, target_group: &str) -> Result<(), Box<dyn Error>> {
    Command::new("dseditgroup")
        .arg("-q") // Quiet mode, suppresses some output
        .arg("-o")
        .arg("edit")
        .arg("-a")
        .arg(group) // The name of the group to add
        .arg("-t")
        .arg("group") // The type of the entity to add, which is a group
        .arg(target_group) // The target group
        .status()?;
    Ok(())
}

/// Deletes the specified group.
pub fn delete_group(group_name: &str) -> Result<(), Box<dyn Error>> {
    let status = Command::new("dseditgroup")
        .arg("-o")
        .arg("delete")
        .arg(group_name)
        .status()?;

    if !status.success() {
        eprintln!("Failed to delete group {}", group_name);
    }
    Ok(())
}
