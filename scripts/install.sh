#!/bin/sh
# Compatibility entry point. Use an absolute path to the trusted CLI binary.
set -eu
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 /absolute/path/to/chmod-bpf [install options]" >&2
    exit 2
fi
binary=$1
shift
case "$binary" in
    /*) exec "$binary" install "$@" ;;
    *) echo "Provide an absolute path to the chmod-bpf binary" >&2; exit 2 ;;
esac
