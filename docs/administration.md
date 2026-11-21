# Administration

## Manage access

Use account short names. When installing from a root shell or deployment agent, specify the accounts that need access. For example, run this command as root to grant access to Alice and Bob without a confirmation prompt.

```sh
chmod-bpf install --user alice --user bob --yes
```

To grant access to every administrator, use `--include-admin`. This adds the `admin` group to `access_bpf`. Combine it with `--user` to grant direct membership to specific users as well. Reinstalling preserves existing memberships.

Once the local group exists, you can change membership without reinstalling the daemon. These commands also work with the local `access_bpf` group used by Wireshark or MacPorts.

```sh
sudo chmod-bpf grant alice
sudo chmod-bpf revoke bob
```

Have affected users log out of macOS and log back in. To investigate access inherited through a group, inspect the local record and check the user's effective directory membership.

```sh
/usr/bin/dscl . -read /Groups/access_bpf
/usr/sbin/dseditgroup -o checkmember -m bob access_bpf
```

If `admin` is nested in `access_bpf` and only specific users should have access, grant those users direct membership before removing the nested group.

```sh
sudo /usr/sbin/dseditgroup -n . -o edit -d admin -t group access_bpf
```

## Daemon and device permissions

The launchd job `com.foctal.chmod-bpf` runs at load and every 60 seconds. Its helper tries to make up to 256 devices available, subject to `debug.bpf_maxdevices`. It applies `root:access_bpf` ownership and mode `0660` to all existing numbered BPF character devices, including those above that limit. New devices may have to wait until the next run.

| Installed file | Purpose |
| --- | --- |
| `/Library/LaunchDaemons/com.foctal.chmod-bpf.plist` | launchd configuration |
| `/Library/Application Support/Foctal/chmod-bpf/chmod-bpf.sh` | Helper run by `/bin/sh` |
| `/Library/Application Support/Foctal/.chmod-bpf.lock` | Lock shared by administrative commands |

The plist and helper are owned by `root:wheel` with mode `0644`. The lock file persists after uninstall. If another command holds the lock, wait for it to finish.

## Upgrades and troubleshooting

After updating the CLI, rerun `install` with the intended accounts to update the installed plist and helper.

- **Installation conflict.** `install` checks for the Wireshark and MacPorts ChmodBPF daemons. If you use a custom launch daemon or an MDM policy, check it separately before switching managers.
- **Unsafe installation path.** Inspect the path named in the error for ownership, group or world write access, symlinks, or extended ACLs.
- **Group lookup mismatch.** Check that Directory Services resolves `access_bpf` to the local group's ID. Resolve any conflicting network group or stale cache before retrying.
- **Incomplete installation.** Run `chmod-bpf check` and review the error. A failed install can leave device permissions or some memberships in place. If the service is registered but its plist or helper is missing, run `uninstall` before reinstalling.
- **Devices still inaccessible.** Run `chmod-bpf check` in a fresh login session. The helper exits between runs. Inspect its registration and recent failure messages with the commands below.

```sh
/bin/launchctl print system/com.foctal.chmod-bpf
/usr/bin/log show --last 15m --style compact --predicate 'eventMessage CONTAINS "BPF permission update failed"'
```

## Uninstall

```sh
sudo chmod-bpf uninstall
```

Uninstall preserves the shared group, its memberships, and current device permissions. To reset existing devices to `root:wheel` with mode `0600`, use `uninstall --revoke-access`. This option refuses to run if a recognized external BPF manager is present. Close any open capture sessions when revoking access, since they retain their open device handles.

To remove the CLI itself, run `cargo uninstall chmod-bpf` for a Cargo installation or delete the prebuilt executable from its installation directory.
