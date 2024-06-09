pub mod app;
pub mod bpf;
pub mod daemon;
pub mod handler;
pub mod permission;
pub mod process;
pub mod resource;
pub mod user;

use app::AppCommands;
use clap::{crate_description, crate_name, crate_version};
use clap::{ArgMatches, Command};

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .format_target(false)
        .init();
    
    let args: ArgMatches = parse_args();
    let subcommand_name = args.subcommand_name().unwrap_or("");
    let app_command = AppCommands::from_str(subcommand_name);

    log::info!("Starting {} v{}", crate_name!(), crate_version!());
    match app_command {
        AppCommands::Check => {
            handler::check_bpf_devices();
        }
        AppCommands::Install => {
            if !privilege::user::privileged() {
                log::error!("This program requires elevated permissions to install the daemon.");
                println!("Please run the program with the 'install' sub-command as root.");
                println!("Example: sudo {} install", crate_name!());
                println!("Exiting...");
                std::process::exit(1);
            }
            handler::install_daemon();
        }
        AppCommands::Uninstall => {
            if !privilege::user::privileged() {
                log::error!("This program requires elevated permissions to uninstall the daemon.");
                println!("Please run the program with the 'uninstall' sub-command as root.");
                println!("Example: sudo {} uninstall", crate_name!());
                println!("Exiting...");
                std::process::exit(1);
            }
            handler::uninstall_daemon();
        }
    }
}

fn parse_args() -> ArgMatches {
    let app: Command = Command::new(crate_name!())
        .version(crate_version!())
        .about(crate_description!())
        // Sub-command for check BPF device permissions
        .subcommand(Command::new("check").about("Check BPF device permissions"))
        // Sub-command for install chmod-bpf daemon
        .subcommand(Command::new("install").about("Install chmod-bpf daemon"))
        // Sub-command for uninstall chmod-bpf daemon
        .subcommand(Command::new("uninstall").about("Uninstall chmod-bpf daemon"));
    app.get_matches()
}
