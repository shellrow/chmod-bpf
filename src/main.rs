mod bpf;
mod command;
mod daemon;
mod handler;
mod output;
mod permission;
mod resource;
mod user;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::{error, info};
use tracing_subscriber::{filter::EnvFilter, fmt::time::ChronoLocal};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Audit BPF permissions, group membership, and daemon configurations.
    Check,
    /// Install the helper launch daemon and supporting assets.
    Install {
        /// Skip interactive confirmation prompts.
        #[arg(short = 'y', long = "yes")]
        assume_yes: bool,
    },
    /// Remove the helper launch daemon and clean up all assets.
    Uninstall {
        /// Skip interactive confirmation prompts.
        #[arg(short = 'y', long = "yes")]
        assume_yes: bool,
    },
}

fn main() {
    if let Err(err) = run() {
        error!(?err, "Command failed");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();

    info!("Launching chmod-bpf");
    match cli.command {
        Commands::Check => handler::check_bpf_devices(),
        Commands::Install { assume_yes } => handler::install_daemon(assume_yes),
        Commands::Uninstall { assume_yes } => handler::uninstall_daemon(assume_yes),
    }
}

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .with_timer(ChronoLocal::new("%Y-%m-%d %H:%M:%S".into()))
        .init();
}
