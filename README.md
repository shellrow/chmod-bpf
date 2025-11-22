[crates-badge]: https://img.shields.io/crates/v/chmod-bpf.svg
[crates-url]: https://crates.io/crates/chmod-bpf
[license-badge]: https://img.shields.io/crates/l/chmod-bpf.svg

# chmod-bpf [![Crates.io][crates-badge]][crates-url] ![License][license-badge]
Managing BPF device permissions on macOS.

`chmod-bpf` is a helper utility that focuses on two things:

* Auditing the current BPF device permissions so you immediately know whether packet capture tools will work.
* Installing or uninstalling the hardened launch daemon, scripts, and groups that keep `/dev/bpf*` devices accessible to trusted operators.

## Features
- Check current BPF device permissions.
- Install and uninstall a daemon to automatically manage BPF device permissions.
- Simple CLI interface for easy interaction.

## Installation
### Install prebuilt binaries via shell script

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/shellrow/chmod-bpf/releases/latest/download/chmod-bpf-installer.sh | sh
```

### Cargo 

```sh
cargo install chmod-bpf
```

### Clone and build
```sh
git clone https://github.com/shellrow/chmod-bpf.git
cd chmod-bpf
cargo build --release
```

## Usage
The CLI exposes three subcommands:

* `check` - Audits BPF permissions, group membership, and known daemon configurations.
* `install` - Installs the launch daemon, helper scripts, and `access_bpf` group. Requires `sudo`.
* `uninstall` - Removes all helper assets and tears down the daemon. Requires `sudo`.

Every administrative subcommand accepts `-y/--yes` to skip the confirmation prompt when you are scripting the tool.

Inspect the current permissions
```sh
chmod-bpf check
```

Install everything
```sh
sudo chmod-bpf install
```

Remove every asset that was previously installed
```sh
sudo chmod-bpf uninstall
```
