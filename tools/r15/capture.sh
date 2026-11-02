#!/bin/sh
# Run on the Mac after the finite load and before reboot; no deploy or gates.
# PEER_LOG=/path/to/operator-peer.log sh tools/r15/capture.sh OUT [en2]
# Optional R15_LOAD_DIR defaults to ~/r15load. OUT must be new or empty.
set -eu
HERE=$(CDPATH= cd "$(dirname "$0")" && pwd)
OUT=${1:?outdir}
IFACE=${2:-en2}
LOAD=${R15_LOAD_DIR:-$HOME/r15load}
PEER_LOG=${PEER_LOG:-$HOME/peer.log}
export PEER_LOG
if [ -d "$OUT" ] && [ -n "$(ls -A "$OUT")" ]; then
    echo "FAIL: output directory must be empty: $OUT" >&2
    exit 1
fi
for f in load.txt client.log flood-client.log token.txt batch.txt; do
    if [ ! -s "$LOAD/$f" ]; then
        echo "FAIL: missing current Round15 load input: $LOAD/$f" >&2
        exit 1
    fi
done
if [ ! -s "$PEER_LOG" ]; then
    echo "FAIL: copy the operator peer log to the Mac and set PEER_LOG first" >&2
    exit 1
fi

# Preserve the established raw ioreg/OBS/RX/system capture, not its old load.
sh "$HERE/../capture-round14.sh" "$OUT" "$IFACE"
mkdir -p "$OUT/r15-load"
for f in "$LOAD"/*; do
    [ -f "$f" ] || continue
    cp -p "$f" "$OUT/r15-load/"
done
# Replace inherited r14load files with the actual finite experiment's records.
for name in load.txt client.log flood-client.log token.txt batch.txt \
            netstat-before.txt netstat-after.txt launchd.out launchd.err; do
    [ ! -f "$LOAD/$name" ] || cp -p "$LOAD/$name" "$OUT/$name"
done
cp -p "$PEER_LOG" "$OUT/peer.log"

# Small installed/loaded version confirmation, separate from the raw evidence.
{
    echo "round15_capture_interface : $IFACE"
    echo "round15_load_source : $LOAD"
    echo "round15_peer_source : $PEER_LOG"
    echo "captured_utc : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# installed binary UUID/hash/version (same system capture)"
    grep -E '^(RTL812xLucy|AMDMapperProbe)_(uuid|sha256|version)' "$OUT/system.txt" || true
    echo "# loaded kext identity (read-only)"
    kmutil showloaded --list-only 2>/dev/null | grep -E 'RTL812|AMDMapperProbe' || true
    echo "# actual post-load route to peer"
    peer=$(awk '/^load_peer /{print $3}' "$OUT/load.txt" | cut -d: -f1)
    [ -z "$peer" ] || route -n get "$peer" 2>/dev/null || true
} > "$OUT/r15-version-confirmation.txt"

# Extract exact probe exports + verify hashes; refresh manifest AFTER overrides.
# This is capture validation only; it does not run either analysis/gate script.
python3 "$HERE/capture-archive.py" "$OUT" "$IFACE"
echo "== Round15 capture complete: $OUT =="
