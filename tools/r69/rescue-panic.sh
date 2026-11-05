#!/bin/sh
# Read the newest kernel panic out of the APFS boot volume, read-only.
set -eu
echo "== available apfs tools =="
command -v apfs-mount || echo "apfs-mount not on PATH"
ls -l /usr/local/sbin/apfs-mount /usr/sbin/mkapfs 2>/dev/null || true

echo "== container =="
lsblk -o NAME,SIZE,FSTYPE,LABEL /dev/sda
