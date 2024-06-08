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
### Cargo 
```
cargo install chmod-bpf
```

### Clone and build
```
git clone https://github.com/shellrow/chmod-bpf.git
cd chmod-bpf
cargo build --release
```

## Usage
### Check BPF device permissions
```
chmod-bpf check
```

### Install the chmod-bpf daemon
```
sudo chmod-bpf install
```

### Uninstall the chmod-bpf daemon
```
sudo chmod-bpf uninstall
```

### Display help information
```
chmod-bpf --help
```
