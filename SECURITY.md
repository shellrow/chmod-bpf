# Security

## Reporting vulnerabilities

Report suspected vulnerabilities privately to shellrow@foctal.com or use GitHub private vulnerability reporting if enabled for this repository. Include the `chmod-bpf` version, macOS version, steps to reproduce the issue, and its impact.

## BPF access

Members of `access_bpf` can capture traffic and inject raw packets. Membership grants access across interfaces. Grant it only to trusted accounts, especially when considering `install --include-admin`.

Removing a direct membership can leave access inherited through another group. Existing processes may retain their session credentials, and changing device permissions leaves open capture handles valid. Close the affected processes and end the user's sessions when immediate revocation is required. See the [administration guide](docs/administration.md) for group inspection and device permission resets.

## Privileged files

The daemon runs its helper as root. Its plist, helper, and their parent directories must be root-owned and free of group or world write permissions, symbolic links, and extended ACLs. The installer also rejects files with multiple hard links. The helper operates only on numbered BPF character devices under `/dev`.
