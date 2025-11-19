use anyhow::{Context, Result, anyhow};
use chrono::Local;
use inquire::Confirm;
use termtree::Tree;
use tracing::{info, warn};

use crate::{
    bpf, daemon,
    output::{self, node_label},
    permission, resource, user,
};

pub fn check_bpf_devices() -> Result<()> {
    let mut tree: Tree<String> = Tree::new(node_label("BPF device audit", None, None));

    info!("Validating BPF device permissions");
    let mut permission_tree = Tree::new(node_label("Permissions", None, None));
    match bpf::check_all_bpf_device_permissions() {
        Ok(_) => {
            permission_tree.push(node_label(
                &output::get_ok_log(output::LOG_LABEL_OK, "Permission"),
                None,
                None,
            ));
            permission_tree.push(node_label(
                &output::get_check_ok_log("You have access to all detected BPF devices."),
                None,
                None,
            ));
        }
        Err(e) => {
            permission_tree.push(node_label(
                &output::get_error_log(output::LOG_LABEL_ERROR, "Permission"),
                None,
                None,
            ));
            permission_tree.push(node_label(
                &output::get_check_error_log(&e.to_string()),
                None,
                None,
            ));
        }
    }
    tree.push(permission_tree);

    info!("Checking current group membership");
    let mut group_tree = Tree::new(node_label("Group", None, None));
    if user::current_user_in_group(bpf::BPF_GROUP) {
        group_tree.push(node_label(
            &output::get_ok_log(output::LOG_LABEL_OK, "Group"),
            None,
            None,
        ));
        group_tree.push(node_label(
            &output::get_check_ok_log(&format!(
                "Current user belongs to {group}",
                group = bpf::BPF_GROUP
            )),
            None,
            None,
        ));
    } else {
        group_tree.push(node_label(
            &output::get_error_log(output::LOG_LABEL_ERROR, "Group"),
            None,
            None,
        ));
        group_tree.push(node_label(
            &output::get_check_error_log(&format!(
                "Current user is not a member of {group}",
                group = bpf::BPF_GROUP
            )),
            None,
            None,
        ));
    }
    tree.push(group_tree);
    info!("Inspecting known daemon configurations");
    let mut daemon_tree = Tree::new(node_label("Daemon", None, None));
    match daemon::check_known_daemon_settings() {
        Ok(plist) => {
            daemon_tree.push(node_label(
                &output::get_ok_log(output::LOG_LABEL_OK, "Daemon"),
                None,
                None,
            ));
            daemon_tree.push(node_label(
                &output::get_check_ok_log(&format!("Found configuration at {plist}")),
                None,
                None,
            ));
        }
        Err(e) => {
            daemon_tree.push(node_label(
                &output::get_error_log(output::LOG_LABEL_ERROR, "Daemon"),
                None,
                None,
            ));
            daemon_tree.push(node_label(
                &output::get_check_error_log(&e.to_string()),
                None,
                None,
            ));
        }
    }
    tree.push(daemon_tree);

    let timestamp = Local::now().to_rfc2822();
    tree.push(node_label("Checked at", Some(&timestamp), Some(" :")));

    println!("\n{}", tree);
    Ok(())
}

pub fn install_daemon(auto_confirm: bool) -> Result<()> {
    user::require_root()?;
    if !confirm_or_skip(auto_confirm, "Install the chmod-bpf launch daemon?")? {
        info!("Installation cancelled by the operator");
        return Ok(());
    }

    info!("Ensuring BPF devices are accessible");
    if let Err(error) = bpf::check_all_bpf_device_permissions() {
        warn!(
            ?error,
            "BPF device permissions check failed; continuing with installation"
        );
    }

    if user::group_exists(bpf::BPF_GROUP) {
        info!("Group {group} already exists", group = bpf::BPF_GROUP);
    } else {
        let gid = user::get_free_gid(user::MIN_GID)?;
        user::create_group(bpf::BPF_GROUP, bpf::BPF_GROUP_NAME, gid)?;
        info!(
            "Created group {group} with gid {gid}",
            group = bpf::BPF_GROUP
        );
    }

    user::add_group_to_group("admin", bpf::BPF_GROUP)?;
    user::add_current_user_to_group(bpf::BPF_GROUP)?;

    std::fs::create_dir_all(resource::CHMOD_BPF_SCRIPT_DIR_PATH).with_context(|| {
        format!(
            "Failed to create script directory at {}",
            resource::CHMOD_BPF_SCRIPT_DIR_PATH
        )
    })?;
    std::fs::write(resource::CHMOD_BPF_SCRIPT_PATH, resource::CHMOD_BPF_SCRIPT).with_context(
        || {
            format!(
                "Failed to write script to {}",
                resource::CHMOD_BPF_SCRIPT_PATH
            )
        },
    )?;

    permission::set_owner_group_recursive(resource::CHMOD_BPF_SCRIPT_DIR_PATH)?;
    permission::set_read_execute_permissions_recursive(resource::CHMOD_BPF_SCRIPT_DIR_PATH)?;

    std::fs::write(resource::CHMOD_BPF_PLIST_PATH, resource::CHMOD_BPF_PLIST).with_context(
        || {
            format!(
                "Failed to write plist to {}",
                resource::CHMOD_BPF_PLIST_PATH
            )
        },
    )?;
    permission::set_read_write_permissions(resource::CHMOD_BPF_PLIST_PATH)?;
    permission::set_owner_group(resource::CHMOD_BPF_PLIST_PATH)?;

    daemon::reload_daemon(resource::CHMOD_BPF_PLIST_PATH)?;
    info!("Installation completed successfully");
    Ok(())
}

pub fn uninstall_daemon(auto_confirm: bool) -> Result<()> {
    user::require_root()?;
    if !confirm_or_skip(auto_confirm, "Uninstall the chmod-bpf launch daemon?")? {
        info!("Uninstallation cancelled by the operator");
        return Ok(());
    }

    daemon::unload_daemon(resource::CHMOD_BPF_PLIST_PATH)?;

    if user::group_exists(bpf::BPF_GROUP) {
        user::delete_group(bpf::BPF_GROUP)?;
        info!("Removed group {group}", group = bpf::BPF_GROUP);
    } else {
        info!("Group {group} was not present", group = bpf::BPF_GROUP);
    }

    match std::fs::remove_dir_all(resource::CHMOD_BPF_SCRIPT_DIR_PATH) {
        Ok(_) => info!(
            "Removed script directory at {path}",
            path = resource::CHMOD_BPF_SCRIPT_DIR_PATH
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            info!("No script directory to remove")
        }
        Err(error) => {
            return Err(anyhow!(
                "Failed to delete script directory at {}: {error}",
                resource::CHMOD_BPF_SCRIPT_DIR_PATH
            ));
        }
    }

    match std::fs::remove_file(resource::CHMOD_BPF_PLIST_PATH) {
        Ok(_) => info!(
            "Removed plist at {path}",
            path = resource::CHMOD_BPF_PLIST_PATH
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            info!("No plist file to remove")
        }
        Err(error) => {
            return Err(anyhow!(
                "Failed to delete plist at {}: {error}",
                resource::CHMOD_BPF_PLIST_PATH
            ));
        }
    }

    info!("Uninstallation completed successfully");
    Ok(())
}

fn confirm_or_skip(auto_confirm: bool, message: &str) -> Result<bool> {
    if auto_confirm {
        return Ok(true);
    }
    let answer = Confirm::new(message)
        .with_default(true)
        .prompt()
        .map_err(|error| anyhow!("{error}"))?;
    Ok(answer)
}
