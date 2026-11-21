# Changelog

## 0.6.0

### Added

- `check --json` reports device access, group membership, and daemon registration. `check --user NAME` can estimate another account's access.
- Administrative commands support `--dry-run`. Use `grant` and `revoke` to manage direct group memberships.
- Shell completions and prebuilt binaries for Apple Silicon and Intel Macs are available.

### Changed

- `check` exits with status `1` when the audit finds a problem.
- `install` grants access to the sudo caller by default. Use `--user` to select accounts or `--include-admin` to include all administrators. Existing memberships, including nested groups, are preserved.
- The helper sets numbered BPF devices to `root:access_bpf` with mode `0660` at boot and every 60 seconds. Rerun `install` after updating the CLI to update the helper.
- `uninstall` preserves the shared group, memberships, and current device permissions. Use `--revoke-access` to restrict devices to root when no other recognized manager is installed.
- Building from source requires Rust 1.88 or later. The `scripts/install.sh` and `scripts/uninstall.sh` wrappers require the CLI's absolute path as their first argument.

### Fixed

- Installation and device revocation work on Darwin devfs without attempting to remove unsupported ACLs.
- Administrative commands validate the sudo caller's identity when selecting the default account. Group creation checks local and network group IDs, and membership changes reject conflicting directory records.
- Installation checks privileged paths and attempts to restore the previous files and service registration if deployment fails.
- Uninstall handles missing services or files and preserves unrelated files in the helper directory.
