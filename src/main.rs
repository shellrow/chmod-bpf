#[cfg(target_os = "macos")]
mod bpf;
#[cfg(target_os = "macos")]
mod command;
#[cfg(target_os = "macos")]
mod daemon;
#[cfg(target_os = "macos")]
mod handler;
#[cfg(target_os = "macos")]
mod installation;
mod output;
#[cfg(target_os = "macos")]
mod permission;
#[cfg(target_os = "macos")]
mod resource;
#[cfg(target_os = "macos")]
mod user;

use anyhow::Result;
use clap::{Args, CommandFactory, Parser, Subcommand};
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    version,
    about,
    after_help = "Run `chmod-bpf check` without sudo to audit your current session.\nPreview administrative changes with --dry-run before applying them."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Args)]
struct MutationOptions {
    /// Apply without an interactive confirmation (required for automation).
    #[arg(short = 'y', long = "yes")]
    assume_yes: bool,
    /// Print the plan without changing files, groups, services, or devices.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Audit access, device security, and launchd registration (exit 1 if unhealthy).
    Check {
        /// Emit a versioned JSON report instead of human-readable output.
        #[arg(long)]
        json: bool,
        /// Audit another account's mode bits and directory membership.
        #[arg(long, value_name = "NAME")]
        user: Option<String>,
    },
    /// Install or repair the daemon and grant access to selected users.
    Install {
        /// Grant access to this user; repeat for multiple users. Without --include-admin, defaults to the sudo caller.
        #[arg(long = "user", value_name = "NAME")]
        users: Vec<String>,
        /// Also grant access to all administrators (opt-in).
        #[arg(long)]
        include_admin: bool,
        #[command(flatten)]
        options: MutationOptions,
    },
    /// Remove this daemon; preserve the shared access_bpf group and memberships.
    Uninstall {
        /// Reset all BPF devices to root:wheel 0600; affects other capture tools.
        #[arg(long)]
        revoke_access: bool,
        #[command(flatten)]
        options: MutationOptions,
    },
    /// Add users to the existing access_bpf group.
    Grant {
        #[arg(required = true, value_name = "USER")]
        users: Vec<String>,
        #[command(flatten)]
        options: MutationOptions,
    },
    /// Remove direct user memberships (inherited group access is unaffected).
    Revoke {
        #[arg(required = true, value_name = "USER")]
        users: Vec<String>,
        #[command(flatten)]
        options: MutationOptions,
    },
    /// Write shell completions to standard output.
    Completions {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(healthy) => ExitCode::from(u8::from(!healthy)),
        Err(error) => {
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::BrokenPipe)
            {
                return ExitCode::SUCCESS;
            }
            eprintln!("Error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<bool> {
    if let Commands::Completions { shell } = cli.command {
        // Generate into memory so a closed stdout is handled like other output.
        let mut buffer = Vec::new();
        clap_complete::generate(shell, &mut Cli::command(), "chmod-bpf", &mut buffer);
        output::write(&buffer)?;
        return Ok(true);
    }
    #[cfg(not(target_os = "macos"))]
    anyhow::bail!("chmod-bpf supports macOS only; no changes were made");
    #[cfg(target_os = "macos")]
    match cli.command {
        Commands::Check { json, user } => handler::check(json, user.as_deref()),
        Commands::Install {
            users,
            include_admin,
            options,
        } => {
            handler::install(users, include_admin, &options)?;
            Ok(true)
        }
        Commands::Uninstall {
            revoke_access,
            options,
        } => {
            handler::uninstall(revoke_access, &options)?;
            Ok(true)
        }
        Commands::Grant { users, options } => {
            handler::membership(users, true, &options)?;
            Ok(true)
        }
        Commands::Revoke { users, options } => {
            handler::membership(users, false, &options)?;
            Ok(true)
        }
        Commands::Completions { .. } => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn administrative_defaults_are_restricted() {
        let cli = Cli::try_parse_from(["chmod-bpf", "install"]).unwrap();
        let Commands::Install {
            users,
            include_admin,
            options,
        } = cli.command
        else {
            panic!()
        };
        assert!(users.is_empty());
        assert!(!include_admin);
        assert!(!options.assume_yes);
        assert!(!options.dry_run);
    }

    #[test]
    fn users_can_be_repeated_and_previewed() {
        let cli = Cli::try_parse_from([
            "chmod-bpf",
            "install",
            "--user",
            "alice",
            "--user",
            "bob",
            "--dry-run",
        ])
        .unwrap();
        let Commands::Install { users, options, .. } = cli.command else {
            panic!()
        };
        assert_eq!(users, ["alice", "bob"]);
        assert!(options.dry_run);
        assert!(Cli::try_parse_from(["chmod-bpf", "grant"]).is_err());
        assert!(Cli::try_parse_from(["chmod-bpf", "install", "--user", "-root"]).is_err());
    }
}
