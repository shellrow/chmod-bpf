#!/bin/sh

# Note: The actual installation and uninstallation processes for chmod-bpf are handled by the Rust binary CLI tool 'chmod-bpf'.
# The install.sh and uninstall.sh scripts are provided as alternative methods for scenarios where manual installation or uninstallation might be necessary.

# This script is used to clean up and remove all components related to the chmod-bpf tool on macOS.
# It will remove the launch daemon, the script files, and the group created for BPF device management.

# Path to the LaunchDaemon plist file for the chmod-bpf service
CHMOD_BPF_PLIST="/Library/LaunchDaemons/com.foctal.chmod-bpf.plist"
# The group used for granting access to BPF devices
BPF_GROUP="access_bpf"

# Stop the launch daemon
launchctl bootout system "$CHMOD_BPF_PLIST"

# Check if the group exists and remove it.
dscl . -read /Groups/"$BPF_GROUP" > /dev/null 2>&1 && \
    dseditgroup -q -o delete "$BPF_GROUP"

# Remove the application support directory which contains the executable and other resources
rm -rf "/Library/Application Support/Foctal/chmod-bpf"

# Delete the LaunchDaemon plist file to clean up system startup entries
rm -f "$CHMOD_BPF_PLIST"
