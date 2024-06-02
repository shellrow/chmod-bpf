#!/bin/sh

#
# Remove the following:
# - The chmod-bpf launch daemon
# - The chmod-bpf script
# - The access_bpf group
#

CHMOD_BPF_PLIST="/Library/LaunchDaemons/com.fortnium.chmod-bpf.plist"
BPF_GROUP="access_bpf"

launchctl bootout system "$CHMOD_BPF_PLIST"

dscl . -read /Groups/"$BPF_GROUP" > /dev/null 2>&1 && \
    dseditgroup -q -o delete "$BPF_GROUP"

rm -rf "/Library/Application Support/Fortnium/chmod-bpf"

rm -f "$CHMOD_BPF_PLIST"
