# Changelog

## 0.6.0

### Added

- JSON audits, meaningful health exit codes, and alternate-account access estimates.
- Administrative dry runs, explicit account selection, `grant`/`revoke`, and shell completions.
- Installation-path validation, a root-controlled administrative lock, atomic updates, and recovery of previous assets and service registration.
- macOS CI for both architectures and Rust 1.88, shell tests, and dependency auditing.

### Changed

- Installation grants access to selected users; all-administrator access requires `--include-admin`. Existing memberships are preserved.
- Uninstall preserves the shared group and device permissions. `--revoke-access` restricts current devices and refuses to compete with another known manager.
- The helper applies root:access_bpf 0660 without ACLs at boot and every 60 seconds.
- Updated dependencies, removed unused UI/logging dependencies, and included Cargo.lock for reproducible builds.
- Version tag pushes build and verify Apple Silicon and Intel archives, checksums, and a shell installer with cargo-dist 0.34.0, then publish them to GitHub Releases.

### Fixed

- Installation and device revocation no longer attempt unsupported ACL removal on Darwin devfs.
- Consistent sudo identity validation and group-ID allocation across local and network records.
- Administrative mutations reject network-only or shadowed access_bpf groups.
- Helper preflight rejects failed or malformed identity and system-limit queries.
- Uninstall tolerates absent services and assets without deleting unrelated files.

### Compatibility

- `check` now returns 1 for unhealthy configurations. Automation must handle this status.
- Reinstall after updating the CLI to update its embedded helper. Review existing users and any legacy nested `admin` group separately.
- Uninstall no longer deletes the shared group or immediately restricts BPF devices by default. Open capture handles remain valid after permission changes.
- Compatibility install/uninstall scripts now require the CLI's absolute path as their first argument.
