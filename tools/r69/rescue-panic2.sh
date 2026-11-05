#!/bin/sh
# Read-only mount of the macOS data volume and copy out the newest panic.
set -eu
M=/mnt/macos
mkdir -p "$M"

echo "== try read-only mount of sda3 =="
if mountpoint -q "$M"; then
    echo "already mounted"
else
    apfs-mount "$M" /dev/sda3 && echo "mounted read-only" || {
        echo "apfs-mount failed"; exit 1; }
fi

echo "== volumes visible =="
ls "$M" || true

echo "== find panic reports =="
find "$M" -maxdepth 6 -type d -name DiagnosticReports 2>/dev/null | head -5
