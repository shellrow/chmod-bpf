#!/bin/sh
# Compatibility entry point. Share the CLI's validation and cleanup behavior.
set -eu
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 /absolute/path/to/chmod-bpf [uninstall options]" >&2
    exit 2
fi
binary=$1
shift
case "$binary" in
    /*) exec "$binary" uninstall "$@" ;;
    *) echo "Provide an absolute path to the chmod-bpf binary" >&2; exit 2 ;;
esac
