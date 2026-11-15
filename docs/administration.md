# Administration

## Installed assets

| Path | Purpose |
| --- | --- |
| `/Library/LaunchDaemons/com.foctal.chmod-bpf.plist` | Root:wheel 0644 launchd configuration. |
| `/Library/Application Support/Foctal/chmod-bpf/chmod-bpf.sh` | Root:wheel 0644 helper, interpreted by `/bin/sh`. |
| `/Library/Application Support/Foctal/.chmod-bpf.lock` | Root-owned administrative lock, retained after uninstall. |

New helper directories are root-owned with mode 0755. The `access_bpf` group is shared and is never deleted by this tool. Local group records must agree with Directory Services name resolution; network-only or shadowed groups are rejected for administrative changes.

Only one BPF manager should be installed. Recognized external managers are `org.wireshark.ChmodBPF` and `org.macports.wireshark.ChmodBPF`. Custom agents and MDM policies are not automatically detected.

## Access management

For deployment agents or root shells, select accounts explicitly:

```sh
sudo /usr/local/bin/chmod-bpf install --user alice --user bob --yes
sudo /usr/local/bin/chmod-bpf grant alice --yes
sudo /usr/local/bin/chmod-bpf revoke bob --yes
```

Use the actual trusted installation path if it differs. Users must log out fully and log back in after membership changes. Removing direct membership does not remove access inherited through another group. Inspect the shared group with:

```sh
/usr/bin/dscl . -read /Groups/access_bpf
/usr/sbin/dseditgroup -o checkmember -m alice access_bpf
```

Older installations may have nested the entire `admin` group. After granting direct memberships to the intended operators, an administrator can remove that policy:

```sh
sudo /usr/sbin/dseditgroup -n . -o edit -d admin -t group access_bpf
```

For immediate revocation, close the affected capture applications and sessions as well. Permission changes do not invalidate open file descriptors.

## Upgrades and recovery

After updating the CLI, preview and rerun `install` with the desired accounts to update its embedded assets. Updating only the binary does not update the installed helper.

Installation runs the helper synchronously before registering the daemon. On failure it attempts to restore previous file contents, permissions, group ownership, and service registration. Recovery failures are reported. If a registered service has missing assets, uninstall it before reinstalling.

Recovery is not a whole-system transaction. Created directories, the shared group, launchd enablement, and device permissions already applied may remain. Memberships are applied last; a failure may leave earlier accounts updated. Inspect the error and `check` output before retrying. Power loss and process termination can interrupt recovery.

Uninstall is safe to repeat. It removes only this daemon's plist and helper, and removes the helper directory only if empty. Unrelated files, the shared group, and memberships are retained. Device permissions remain until recreation, usually at reboot, unless `--revoke-access` is supplied.

The lock file's existence does not indicate a running operation. Kernel locks are released when the owning process exits. Do not delete an active lock file to bypass contention; wait for the other operation to finish.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| Access denied after a grant | Fully log out/in, then run `check` without sudo. |
| Configuration exists but service is unregistered | Rerun this tool's `install`, or use the external manager's original installer. |
| Competing manager detected | Keep one manager and remove the other with its installer. |
| Unsafe installation path | Review ownership, write permissions, links, and ACLs manually. |
| Newly created nodes are inaccessible | Wait for the next helper pass; check for helper failures if the problem persists. |
| Registered daemon is not running | Normal between passes; inspect devices and helper diagnostics. |

Read-only diagnostics:

```sh
chmod-bpf check --json
/bin/launchctl print system/com.foctal.chmod-bpf
/usr/bin/log show --last 15m --style compact --predicate 'eventMessage CONTAINS "chmod-bpf"'
/usr/sbin/sysctl -n debug.bpf_maxdevices
```

The helper logs failures with the `chmod-bpf` tag. `launchctl print` output is for human inspection; its text format is not a stable API.

The compatibility scripts `scripts/install.sh` and `scripts/uninstall.sh` require an absolute path to the CLI as their first argument and forward the remaining options.
