#!/bin/sh

chown -R root:wheel "/Library/Application Support/Fortnium/chmod-bpf"
chmod -R a+rX,go-w "/Library/Application Support/Fortnium/chmod-bpf"

CHMOD_BPF_PLIST="/Library/LaunchDaemons/com.fortnium.chmod-bpf.plist"
BPF_GROUP="access_bpf"
BPF_GROUP_NAME="BPF device access ACL"
min_gid=100

if ! dscl . -read /Groups/"$BPF_GROUP" > /dev/null 2>&1; then
   free_gid=$(dscl . -list /Groups PrimaryGroupID | sort -bnk2 | awk -v min_gid=$min_gid 'BEGIN{i=min_gid}{if($2==i)i++}END{print i}')
   dseditgroup -q -o create -i $free_gid -r "$BPF_GROUP_NAME" "$BPF_GROUP"
fi

dseditgroup -q -o edit -a admin -t group "$BPF_GROUP"
dseditgroup -q -o edit -a "$USER" -t user "$BPF_GROUP"

chmod u=rw,g=r,o=r "$CHMOD_BPF_PLIST"
chown root:wheel "$CHMOD_BPF_PLIST"

# Try to bootout and bootstrap
launchctl bootout system "$CHMOD_BPF_PLIST" > /dev/null 2>&1

launchctl bootstrap system "$CHMOD_BPF_PLIST"
