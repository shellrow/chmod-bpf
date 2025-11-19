#!/bin/sh

# Note: The actual installation and uninstallation processes for chmod-bpf are handled by the Rust binary CLI tool 'chmod-bpf'.
# The install.sh and uninstall.sh scripts are provided as alternative methods for scenarios where manual installation or uninstallation might be necessary.

# This script configures the permissions for the chmod-bpf application and its associated launch daemon on macOS.

# Set the owner to root and remove write permissions for group and others,
# and ensure that all files are readable and directories are accessible.
chown -R root:wheel "/Library/Application Support/Foctal/chmod-bpf"
chmod -R a+rX,go-w "/Library/Application Support/Foctal/chmod-bpf"

# Variables for plist and group management
CHMOD_BPF_PLIST="/Library/LaunchDaemons/com.foctal.chmod-bpf.plist"
BPF_GROUP="access_bpf"
BPF_GROUP_NAME="BPF Device ACL"
min_gid=100

# Create the BPF group if it doesn't already exist, starting with the first available GID above 100
if ! dscl . -read /Groups/"$BPF_GROUP" > /dev/null 2>&1; then
   free_gid=$(dscl . -list /Groups PrimaryGroupID | sort -bnk2 | awk -v min_gid=$min_gid 'BEGIN{i=min_gid}{if($2==i)i++}END{print i}')
   dseditgroup -q -o create -i $free_gid -r "$BPF_GROUP_NAME" "$BPF_GROUP"
fi

# Add 'admin' and the current user to the BPF group to allow administration of BPF devices
dseditgroup -q -o edit -a admin -t group "$BPF_GROUP"
dseditgroup -q -o edit -a "$USER" -t user "$BPF_GROUP"

# Set permissions on the Launch Daemon plist file to read-write for owner,
# and read-only for group and others.
chmod u=rw,g=r,o=r "$CHMOD_BPF_PLIST"
chown root:wheel "$CHMOD_BPF_PLIST"

# Ensure the daemon is not running before attempting to load it,
# to avoid conflicts or errors.
launchctl bootout system "$CHMOD_BPF_PLIST" > /dev/null 2>&1

# Load the Launch Daemon to start managing BPF device permissions automatically at boot.
launchctl bootstrap system "$CHMOD_BPF_PLIST"
