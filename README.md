# chmod-bpf

`chmod-bpf` lets trusted users capture packets on macOS without running capture applications as root. A launch daemon gives members of the local `access_bpf` group read and write access to Berkeley Packet Filter (BPF) devices. This access also permits raw packet injection.

## Install the CLI

Run the installer as your regular user on Apple Silicon or Intel Macs.

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/shellrow/chmod-bpf/releases/latest/download/chmod-bpf-installer.sh | sh
```

The installer places `chmod-bpf` in `$CARGO_HOME/bin` (normally `~/.cargo/bin`). Follow its instructions to add that directory to your `PATH`.

For manual installation, download the archive and matching `.sha256` file for your Mac (`aarch64` for Apple Silicon or `x86_64` for Intel) from [GitHub Releases](https://github.com/shellrow/chmod-bpf/releases). In the download directory, run `shasum -a 256 -c` with the checksum filename. After verification, extract the archive and place `chmod-bpf` on your `PATH`.

With Rust 1.88 or later, you can also install the CLI through Cargo.

```sh
cargo install chmod-bpf --locked
```

## Set up packet capture

Run `chmod-bpf check` without sudo to see whether your account already has access. If Wireshark or MacPorts already manages BPF permissions, keep using that manager or remove it with its original installer before installing this daemon.

Preview the changes, then install the daemon and grant access to the account invoking sudo.

```sh
chmod-bpf install --dry-run
sudo chmod-bpf install
```

Log out of macOS and log back in so your session picks up the new group membership. Then verify access as the user who will run the capture application.

```sh
chmod-bpf check
```

## Commands

| Command | Description |
| --- | --- |
| `check [--json] [--user NAME]` | Check device permissions, account access, and daemon registration. |
| `install [--user NAME] [--include-admin]` | Install or repair the daemon. Repeat `--user` to grant access to several accounts. |
| `grant USER...` | Add users to the existing local `access_bpf` group. |
| `revoke USER...` | Remove direct group memberships. Users may still inherit access through another group. |
| `uninstall [--revoke-access]` | Remove the daemon and helper. Add `--revoke-access` to restrict existing BPF devices to root. |
| `completions SHELL` | Print completions for Bash, Zsh, Fish, Elvish, or PowerShell. |

Commands that change the system require root. Use `--dry-run` to preview them without sudo. Use `--yes` (`-y`) to skip confirmation when running noninteractively.

## Audit results

A healthy audit finds at least one numbered BPF device. All devices must be readable and writable by the selected account, owned by `root:access_bpf`, and set to mode `0660` with no extended ACLs. The account must belong to `access_bpf`, and exactly one recognized daemon must be installed and registered. For its own daemon, `chmod-bpf` also verifies the installed helper and configuration against the copies in the CLI.

For the current user, `check` tests OS permissions without opening a device. When checking a different user, including the original caller under sudo, it estimates access from directory group membership and device mode bits. A capture also needs a free device.

`chmod-bpf check --json` writes the report to standard output, including when the audit finds problems. The report includes `schema_version` (currently `1`), `healthy`, `issues`, and `access_evaluation`. The exit status is `0` for a healthy audit, `1` for an unhealthy audit or command failure, and `2` for invalid arguments.

See the [administration guide](docs/administration.md) for group management, upgrades, troubleshooting, and removal.

## License

[MIT](LICENSE)
