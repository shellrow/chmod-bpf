use std::path::PathBuf;
use termtree::Tree;
use crate::output::{self, node_label};

use crate::{
    bpf, daemon, permission, resource,
    user::{self, group_exists},
};
use inquire::Confirm;

pub fn check_bpf_devices() {
    let mut tree: Tree<String> = Tree::new(node_label("BPF device check result", None, None));
    // 1. Check if the user has the required permissions for all BPF devices.
    log::info!("Checking BPF device permissions...");
    let mut permission_tree: Tree<String>;
    match bpf::check_all_bpf_device_permissions() {
        Ok(_) => {
            let message: &str = "You have the required permissions for All BPF devices.";
            log::info!("{message}");
            permission_tree = Tree::new(node_label(&output::get_ok_log(output::LOG_LABEL_OK, "Permission"), None, None));
            permission_tree.push(node_label(&output::get_check_ok_log(message), None, None));
        }
        Err(e) => {
            log::error!("{}", e);
            permission_tree = Tree::new(node_label(&output::get_error_log(output::LOG_LABEL_ERROR, "Permission"), None, None));
            permission_tree.push(node_label(&output::get_check_error_log(&e), None, None));
        }
    }
    tree.push(permission_tree);
    
    // 2. Check if the BPF devices are owned by the correct group.
    log::info!("Checking BPF device groups...");
    let mut group_tree: Tree<String>;
    if user::current_user_in_group(bpf::BPF_GROUP) {
        let message: String = format!("Current user is in the BPF group: {}", bpf::BPF_GROUP);
        let message: &str = message.as_str();
        log::info!("{message}");
        group_tree = Tree::new(node_label(&output::get_ok_log(output::LOG_LABEL_OK, "Group"), None, None));
        group_tree.push(node_label(&output::get_check_ok_log(message), None, None));
    } else {
        let message: String = format!("Current user is not in the BPF group: {}", bpf::BPF_GROUP);
        let message: &str = message.as_str();
        log::error!("{message}");
        group_tree = Tree::new(node_label(&output::get_error_log(output::LOG_LABEL_ERROR, "Group"), None, None));
        group_tree.push(node_label(&output::get_check_error_log(message), None, None));
    }
    tree.push(group_tree);
    // 3. Check if the known daemon settings exist. (e.g. Wireshark)
    log::info!("Checking for known daemon settings...");
    let mut daemon_tree: Tree<String>;
    match daemon::check_known_daemon_settings() {
        Ok(plist) => {
            let message: String = format!("Found known daemon settings: {}", plist);
            let message: &str = message.as_str();
            log::info!("{message}");
            daemon_tree = Tree::new(node_label(&output::get_ok_log(output::LOG_LABEL_OK, "Daemon"), None, None));
            daemon_tree.push(node_label(&output::get_check_ok_log(message), None, None));
        }
        Err(e) => {
            let message: String = format!("Failed to find known daemon settings: {}", e);
            let message: &str = message.as_str();
            log::error!("{message}");
            daemon_tree = Tree::new(node_label(&output::get_error_log(output::LOG_LABEL_ERROR, "Daemon"), None, None));
            daemon_tree.push(node_label(&output::get_check_error_log(message), None, None));
        }
    }
    tree.push(daemon_tree);
    
    println!();
    println!("{}", tree);
}

pub fn install_daemon() {
    // Ask the user if they want to proceed with the installation.
    let ans: bool = Confirm::new("Do you want to proceed with the installation?")
        .prompt()
        .unwrap();
    if ans == false {
        log::info!("Exiting...");
        std::process::exit(0);
    }
    // 1. Check if the user has the required permissions for all BPF devices.
    log::info!("Checking BPF device permissions...");
    match bpf::check_all_bpf_device_permissions() {
        Ok(_) => {
            log::info!("You have the required permissions for All BPF devices.");
            let ans: bool = Confirm::new("Do you want to proceed with the installation?")
                .prompt()
                .unwrap();
            if ans == false {
                log::info!("Exiting...");
                std::process::exit(0);
            }
        }
        Err(e) => {
            log::error!("{}", e);
        }
    }

    log::info!("Installing daemon...");

    // 2. Create the BPF group if it doesn't exist.
    if group_exists(bpf::BPF_GROUP) {
        log::info!("Group {} already exists.", bpf::BPF_GROUP);
    } else {
        log::info!("Creating group {}...", bpf::BPF_GROUP);
        let new_gid = match user::get_free_gid(user::MIN_GID) {
            Ok(gid) => gid,
            Err(e) => {
                log::error!("Failed to get free GID: {}", e);
                std::process::exit(1);
            }
        };
        match user::create_group(bpf::BPF_GROUP, bpf::BPF_GROUP_NAME, new_gid) {
            Ok(_) => {
                log::info!("Group {} created successfully.", bpf::BPF_GROUP);
            }
            Err(e) => {
                log::error!("Failed to create group {}: {}", bpf::BPF_GROUP, e);
                std::process::exit(1);
            }
        }
    }
    // 3. Change the group of the BPF devices to the BPF group.
    log::info!("Changing BPF device groups...");
    match user::add_group_to_group("admin", bpf::BPF_GROUP) {
        Ok(_) => {
            log::info!("Group {} added to group admin.", bpf::BPF_GROUP);
        }
        Err(e) => {
            log::error!(
                "Failed to add group {} to group admin: {}",
                bpf::BPF_GROUP,
                e
            );
            std::process::exit(1);
        }
    }
    match user::add_current_user_to_group(bpf::BPF_GROUP) {
        Ok(_) => {
            log::info!("Current user added to group {}.", bpf::BPF_GROUP);
        }
        Err(e) => {
            log::error!(
                "Failed to add current user to group {}: {}",
                bpf::BPF_GROUP,
                e
            );
            std::process::exit(1);
        }
    }
    // 4. Create the script to change the BPF device permissions.
    log::info!("Creating script to change BPF device permissions...");
    let script_dir_path = PathBuf::from(resource::CHMOD_BPF_SCRIPT_DIR_PATH);
    match std::fs::create_dir_all(script_dir_path) {
        Ok(_) => {
            log::info!(
                "Script directory created at {}.",
                resource::CHMOD_BPF_SCRIPT_DIR_PATH
            );
        }
        Err(e) => {
            log::error!(
                "Failed to create script directory at {}: {}",
                resource::CHMOD_BPF_SCRIPT_DIR_PATH,
                e
            );
            std::process::exit(1);
        }
    }
    let script_path = PathBuf::from(resource::CHMOD_BPF_SCRIPT_PATH);
    match std::fs::write(&script_path, resource::CHMOD_BPF_SCRIPT.to_owned()) {
        Ok(_) => {
            log::info!("Script saved to {}.", resource::CHMOD_BPF_SCRIPT_PATH);
        }
        Err(e) => {
            log::error!(
                "Failed to save script to {}: {}",
                resource::CHMOD_BPF_SCRIPT_PATH,
                e
            );
            std::process::exit(1);
        }
    }
    // 5. Set permissions for the script.
    log::info!("Setting permissions for the script...");
    match permission::set_owner_group_recursive(resource::CHMOD_BPF_SCRIPT_DIR_PATH) {
        Ok(_) => {
            log::info!("Owner and group set for script directory.");
        }
        Err(e) => {
            log::error!("Failed to set owner and group for script directory: {}", e);
            std::process::exit(1);
        }
    }
    match permission::set_read_execute_permissions_recursive(resource::CHMOD_BPF_SCRIPT_DIR_PATH) {
        Ok(_) => {
            log::info!("Read and execute permissions set for script directory.");
        }
        Err(e) => {
            log::error!(
                "Failed to set read and execute permissions for script directory: {}",
                e
            );
            std::process::exit(1);
        }
    }
    // 6. Create the launch daemon plist file.
    log::info!("Creating launch daemon plist file...");
    let plist_path = PathBuf::from(resource::CHMOD_BPF_PLIST_PATH);
    match std::fs::write(&plist_path, resource::CHMOD_BPF_PLIST.to_owned()) {
        Ok(_) => {
            log::info!("Plist saved to {}.", resource::CHMOD_BPF_PLIST_PATH);
        }
        Err(e) => {
            log::error!(
                "Failed to save plist to {}: {}",
                resource::CHMOD_BPF_PLIST_PATH,
                e
            );
            std::process::exit(1);
        }
    }
    // 7. Set permissions for the plist file.
    log::info!("Setting permissions for the plist file...");
    match permission::set_read_write_permissions(resource::CHMOD_BPF_PLIST_PATH) {
        Ok(_) => {
            log::info!("Read and write permissions set for plist file.");
        }
        Err(e) => {
            log::error!(
                "Failed to set read and write permissions for plist file: {}",
                e
            );
            std::process::exit(1);
        }
    }
    match permission::set_owner_group(resource::CHMOD_BPF_PLIST_PATH) {
        Ok(_) => {
            log::info!("Owner and group set for plist file.");
        }
        Err(e) => {
            log::error!("Failed to set owner and group for plist file: {}", e);
            std::process::exit(1);
        }
    }
    // 8. Load the launch daemon plist file.
    log::info!("Loading launch daemon plist file...");
    match daemon::reload_daemon(resource::CHMOD_BPF_PLIST_PATH) {
        Ok(_) => {
            log::info!("Daemon reloaded successfully.");
        }
        Err(e) => {
            log::error!("Failed to reload daemon: {}", e);
            std::process::exit(1);
        }
    }
    log::info!("Daemon installed successfully.");
}

pub fn uninstall_daemon() {
    // Ask the user if they want to proceed with the uninstallation.
    let ans: bool = Confirm::new("Do you want to proceed with the uninstallation?")
        .prompt()
        .unwrap();
    if ans == false {
        log::info!("Exiting...");
        std::process::exit(0);
    }
    // 1. Unload the launch daemon plist file.
    log::info!("Unloading launch daemon plist file...");
    match daemon::unload_daemon(resource::CHMOD_BPF_PLIST_PATH) {
        Ok(_) => {
            log::info!("Daemon unloaded successfully.");
        }
        Err(e) => {
            log::error!("Failed to unload daemon: {}", e);
            std::process::exit(1);
        }
    }
    // 2. Delete BPF group.
    log::info!("Deleting BPF group...");
    match user::delete_group(bpf::BPF_GROUP) {
        Ok(_) => {
            log::info!("Group {} deleted successfully.", bpf::BPF_GROUP);
        }
        Err(e) => {
            log::error!("Failed to delete group {}: {}", bpf::BPF_GROUP, e);
            std::process::exit(1);
        }
    }
    // 3. Delete the script to change the BPF device permissions.
    log::info!("Deleting script to change BPF device permissions...");
    let script_dir_path = PathBuf::from(resource::CHMOD_BPF_SCRIPT_DIR_PATH);
    match std::fs::remove_dir_all(script_dir_path) {
        Ok(_) => {
            log::info!("Script directory deleted.");
        }
        Err(e) => {
            log::error!("Failed to delete script directory: {}", e);
            std::process::exit(1);
        }
    }
    // 4. Delete the launch daemon plist file.
    log::info!("Deleting launch daemon plist file...");
    let plist_path = PathBuf::from(resource::CHMOD_BPF_PLIST_PATH);
    match std::fs::remove_file(plist_path) {
        Ok(_) => {
            log::info!("Plist file deleted.");
        }
        Err(e) => {
            log::error!("Failed to delete plist file: {}", e);
            std::process::exit(1);
        }
    }
    log::info!("Daemon uninstalled successfully.");
}
