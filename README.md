# chmod-bpf

[![Crates.io](https://img.shields.io/crates/v/chmod-bpf.svg)](https://crates.io/crates/chmod-bpf)
[![License](https://img.shields.io/crates/l/chmod-bpf.svg)](LICENSE)

Manage macOS BPF permissions so trusted users can capture packets without running capture applications as root. The CLI audits access, manages group membership, and installs a launch daemon to maintain device permissions.

BPF access permits packet capture and raw packet injection. Grant it only to trusted users.

## Installation

Install the prebuilt CLI without sudo:

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/shellrow/chmod-bpf/releases/latest/download/chmod-bpf-installer.sh | sh
```

The installer selects Apple Silicon or Intel and installs to `$CARGO_HOME/bin` (by default, `~/.cargo/bin`). Follow its instructions to update your shell's `PATH`. Installing the CLI alone does not change system permissions.

Alternatively, install with Rust 1.88 or newer:

```sh
cargo install chmod-bpf --locked
```

For a local source checkout, use `cargo install --path . --locked`.

For manual installation, download the matching archive and its `.sha256` file from [GitHub Releases](https://github.com/shellrow/chmod-bpf/releases). Choose `aarch64` for Apple Silicon or `x86_64` for Intel. Run `shasum -a 256 -c <archive>.sha256`, extract the archive, and place `chmod-bpf` on your `PATH`. Prebuilt binaries do not require Rust. CI tests both architectures on macOS 15; other macOS versions require separate validation.

The shell installer verifies checksums when `sha256sum` is available. Otherwise, it skips verification; use the manual procedure above to verify with macOS's `shasum`.

## Quick start

```sh
chmod-bpf check
chmod-bpf install --dry-run
sudo "$(command -v chmod-bpf)" install
```

Using the absolute executable path avoids differences between your `PATH` and sudo's. Installation grants access to the original sudo caller. Log out fully and log back in, then run `chmod-bpf check` without sudo.

If Wireshark's or MacPorts' BPF manager is installed, use that manager or remove it with its original installer first. `install` refuses to compete with either. `check`, `grant`, and `revoke` can be used with an existing local `access_bpf` group.

## Commands

| Command | Purpose |
| --- | --- |
| `check [--json] [--user NAME]` | Audit device access, permissions, membership, and daemon registration. |
| `install [--user NAME] [--include-admin]` | Install or repair the daemon. Repeat `--user` for multiple accounts. |
| `grant USER...` | Add direct memberships to the local `access_bpf` group. |
| `revoke USER...` | Remove direct memberships; inherited access is unaffected. |
| `uninstall [--revoke-access]` | Remove this daemon and its assets. Optionally restrict current BPF devices. |
| `completions SHELL` | Print completions for Bash, Zsh, Fish, Elvish, or PowerShell. |

Administrative commands accept `--dry-run` to validate and preview changes without sudo, and `-y`/`--yes` to skip confirmation. Noninteractive changes require `--yes`. Interactive confirmation defaults to No.

```sh
chmod-bpf install --user alice --user bob --dry-run
sudo "$(command -v chmod-bpf)" install --user alice --user bob --yes
sudo "$(command -v chmod-bpf)" revoke bob --yes
```

Use account short names. Root shells and deployment agents must specify `--user` or `--include-admin`. The latter grants access to all administrators and does not add an implicit user. Reinstalling preserves existing memberships, including any previously nested `admin` group.

## Audit output

Run `check` as the capture operator. It uses the OS access check without opening a BPF device. Reports for another account, including the original caller under sudo, use directory groups and mode bits when the account differs from the process identity. These reports are labeled `directory_mode_estimate`; they cannot verify that account's current session credentials.

A healthy result requires accessible devices with `root:access_bpf 0660` permissions and no ACLs, group membership, and exactly one registered known daemon with its configuration present. This tool's own installed assets must also match the CLI version. A registered one-shot daemon need not be running between passes. Device checks do not guarantee that a subsequent capture can open a free node.

| Exit code | Meaning |
| --- | --- |
| `0` | Healthy audit, completed command, successful preview, or interactive cancellation. |
| `1` | Unhealthy audit, failed operation, or unsupported platform. |
| `2` | Invalid arguments. |

`check --json` writes a report to stdout even for an unhealthy audit. `schema_version` is `1`; consumers should accept additional fields and reject unsupported versions. The report includes the account, evaluation method, group, devices, daemon registrations, issues, and hints. Mutation commands use text output. Command errors go to stderr.

```sh
chmod-bpf check --json > bpf-audit.json
```

## Operation and removal

The helper runs at boot and every 60 seconds. It pre-creates up to 256 BPF devices, bounded by the system limit, then sets all existing numbered BPF character devices to `root:access_bpf 0660`. Darwin devfs does not support extended ACLs, so the helper does not attempt ACL removal. New devices may remain inaccessible until the next pass; timers can be delayed during sleep.

```sh
chmod-bpf uninstall --dry-run
sudo "$(command -v chmod-bpf)" uninstall --yes
```

Uninstall preserves the shared group, memberships, and current device permissions. Use `--revoke-access` to reset devices to `root:wheel 0600` without ACLs; this refuses to run alongside another known manager. Neither group changes nor permission changes revoke already-open capture handles. Remove the CLI separately with `cargo uninstall chmod-bpf` if installed through Cargo. For a prebuilt installation, delete the executable from its installation directory.

## License

[MIT](LICENSE).
