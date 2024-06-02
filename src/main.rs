pub mod user;
pub mod bpf;
pub mod daemon;

fn main() {
    match bpf::check_all_bpf_device_permissions() {
        Ok(_) => println!("All BPF devices have correct permissions."),
        Err(e) => eprintln!("Error: {}", e),
    }
    if user::current_user_in_group(bpf::BPF_GROUP) {
        println!("User is in the BPF group.");
    } else {
        println!("User is not in the BPF group.");
    }
    if daemon::known_daemon_setting_exists() {
        println!("Known daemon settings found.");
    } else {
        println!("Known daemon settings not found.");
    }
}
