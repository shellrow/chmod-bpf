#!/bin/sh
# Manage only numbered BPF character devices. Run as root via launchd.
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
umask 077
report_exit() {
    result=$?
    trap - 0
    if [ "$result" -ne 0 ]; then
        /usr/bin/logger -t chmod-bpf "BPF permission update failed (exit $result)" || :
    fi
    exit "$result"
}
trap report_exit 0

uid=$(/usr/bin/id -u)
if [ "$uid" != 0 ]; then
    echo "chmod-bpf: this helper requires root" >&2
    exit 1
fi

maximum=$(/usr/sbin/sysctl -n debug.bpf_maxdevices)
case "$maximum" in
    ''|*[!0-9]*) echo "chmod-bpf: invalid debug.bpf_maxdevices" >&2; exit 1 ;;
esac
if [ "${#maximum}" -gt 10 ] || [ "$maximum" -lt 1 ]; then
    echo "chmod-bpf: debug.bpf_maxdevices is out of range" >&2
    exit 1
fi
limit=256
if [ "$maximum" -lt "$limit" ]; then limit=$maximum; fi

# Opening a node causes Darwin to create the next one. A busy node may refuse
# the open while remaining a valid device whose permissions can be updated.
index=0
while [ "$index" -lt "$limit" ]; do
    device=/dev/bpf$index
    if [ -L "$device" ] || { [ -e "$device" ] && [ ! -c "$device" ]; }; then
        echo "chmod-bpf: refusing unexpected file type at $device" >&2
        exit 1
    fi
    next=$((index + 1))
    if [ "$next" -lt "$limit" ] && [ ! -c "/dev/bpf$next" ]; then
        ( : < "$device" ) 2>/dev/null || :
    fi
    index=$next
done

set --
for device in /dev/bpf[0-9]*; do
    suffix=${device#/dev/bpf}
    case "$suffix" in ''|*[!0-9]*) continue ;; esac
    if [ -L "$device" ] || [ ! -c "$device" ]; then
        echo "chmod-bpf: expected a character device at $device" >&2
        exit 1
    fi
    set -- "$@" "$device"
done
if [ "$#" -eq 0 ]; then
    echo "chmod-bpf: no BPF devices were found" >&2
    exit 1
fi

# Darwin devfs has no extended ACLs. chmod -N fails with ENOTSUP even when
# there is no ACL, so apply only ownership and mode changes to these devices.
/usr/sbin/chown root:access_bpf "$@"
/bin/chmod 0660 "$@"
