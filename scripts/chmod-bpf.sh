#! /bin/zsh
# shellcheck shell=bash

#
# This script will:
# pre-create a number of BPF devices, then make them owned by
# the access_bpf group, with permissions rw-rw----, so that
# anybody in the access_bpf group can use programs that capture
# or send raw packets.
#

# Pre-create BPF devices. Set to 0 to disable.
FORCE_CREATE_BPF_MAX=256

SYSCTL_MAX=$( sysctl -n debug.bpf_maxdevices )
if [ "$FORCE_CREATE_BPF_MAX" -gt "$SYSCTL_MAX" ] ; then
	FORCE_CREATE_BPF_MAX=$SYSCTL_MAX
fi

syslog -s -l notice "chmod-bpf: Forcing creation and setting permissions for /dev/bpf0-$(( FORCE_CREATE_BPF_MAX - 1))"

CUR_DEV=0
while [ "$CUR_DEV" -lt "$FORCE_CREATE_BPF_MAX" ] ; do
	read -r -n 0 < /dev/bpf$CUR_DEV > /dev/null 2>&1
	CUR_DEV=$(( CUR_DEV + 1 ))
done

chgrp access_bpf /dev/bpf*
chmod g+rw /dev/bpf*
