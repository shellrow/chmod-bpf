[crates-badge]: https://img.shields.io/crates/v/chmod-bpf.svg
[crates-url]: https://crates.io/crates/chmod-bpf
[license-badge]: https://img.shields.io/crates/l/chmod-bpf.svg

# chmod-bpf [![Crates.io][crates-badge]][crates-url] ![License][license-badge]
Managing BPF device permissions on macOS.  
This tool provides a simple way to check, set, or remove permissions for BPF devices to enhance security and ease of management for developers and system administrators.

## Features
- Check current BPF device permissions.
- Install and uninstall a daemon to automatically manage BPF device permissions.
- Simple CLI interface for easy interaction.

## Installation
### Install prebuilt binaries via shell script

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/shellrow/chmod-bpf/releases/latest/download/chmod-bpf-installer.sh | sh
```

### Install prebuilt binaries via Homebrew

```sh
brew install shellrow/tap-chmod-bpf/chmod-bpf
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
### Check BPF device permissions
```sh
chmod-bpf check
```

### Install the chmod-bpf daemon
```sh
sudo chmod-bpf install
```

### Uninstall the chmod-bpf daemon
```sh
sudo chmod-bpf uninstall
```

### Display help information
```sh
chmod-bpf --help
```
