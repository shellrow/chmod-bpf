#! /bin/zsh
# shellcheck shell=bash

# Description:
# This script is designed to manage Berkeley Packet Filter (BPF) devices on macOS.
# It pre-creates a specified number of BPF devices and configures their ownership
# and permissions to allow designated group members to capture and send raw packets.

# Purpose:
# - Pre-create a defined number of BPF devices up to the system's maximum.
# - Assign ownership of these devices to the 'access_bpf' group.
# - Set permissions to read-write for the group, allowing packet capture and transmission.

# Maximum number of BPF devices to pre-create, set to 256 by default.
# Can be adjusted as needed but should not exceed the system maximum.
FORCE_CREATE_BPF_MAX=256

# Fetch the system's maximum number of BPF devices to ensure we do not exceed this.
SYSCTL_MAX=$( sysctl -n debug.bpf_maxdevices )
if [ "$FORCE_CREATE_BPF_MAX" -gt "$SYSCTL_MAX" ] ; then
	FORCE_CREATE_BPF_MAX=$SYSCTL_MAX
fi

# Log the action of configuring BPF devices.
syslog -s -l notice "chmod-bpf: Forcing creation and setting permissions for /dev/bpf0-$(( FORCE_CREATE_BPF_MAX - 1))"

# Loop through and pre-create BPF devices up to the determined maximum.
# This loop ensures that each device is ready and accessible by the 'access_bpf' group.
CUR_DEV=0
while [ "$CUR_DEV" -lt "$FORCE_CREATE_BPF_MAX" ] ; do
	read -r -n 0 < /dev/bpf$CUR_DEV > /dev/null 2>&1
	CUR_DEV=$(( CUR_DEV + 1 ))
done

# Set the group to 'access_bpf' and grant group members read-write permissions.
chgrp access_bpf /dev/bpf*
chmod g+rw /dev/bpf*
