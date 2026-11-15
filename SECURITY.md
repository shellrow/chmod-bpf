# Security

BPF access permits packet capture and raw packet injection. It is not restricted to a single interface or to capture-only operations. Grant `access_bpf` membership only to trusted users.

## Privileges and installed files

Administrative operations require effective UID 0. The sudo caller is selected only when `SUDO_USER` and `SUDO_UID` agree; unprivileged callers cannot use these variables to select another identity. An already privileged caller remains trusted to select accounts.

Child commands use absolute system paths, a cleared environment, and no inherited stdin. The helper runs through `/bin/sh` without user shell startup files.

Installation paths must be root-owned, have no group/world write bits or extended ACLs, and contain no symbolic links. Assets must be regular, singly linked files. Updates use staged files and atomic replacement; cleanup does not recursively delete directories. Administrative commands share a kernel lock. These protections exclude concurrent changes by another root process or external management system.

The helper accepts only numbered BPF character devices and rejects symlinks. It manages exact ownership and permissions. Darwin's devfs does not support extended ACLs; the helper does not attempt ACL removal. Audits still reject unexpected device ACLs, and installation paths are checked separately. Unknown third-party managers and root-created replacement device nodes are outside its trust boundary. See [administration](docs/administration.md) for recovery limits.

## Auditing and revocation

Current-account audits check OS permissions without opening BPF nodes. Alternate-account audits are mode-bit estimates. Neither guarantees that a later capture can open a free device or that application-specific restrictions permit capture.

Group and permission changes do not revoke open file descriptors. Close affected capture processes or sessions when immediate revocation is required. Uninstall preserves shared memberships and, by default, current device permissions; review the remaining access policy when decommissioning.

## Reporting vulnerabilities

Use the repository's private vulnerability-reporting facility if enabled, or contact shellrow@foctal.com. Include the tool and macOS versions, reproduction steps, and impact. Avoid publishing exploit details before the maintainer can assess the report.
