#!/bin/sh
# Round20 capture only. Run on the Mac after the finite load finished and the
# probe reported its TX cleanup, before rebooting.
# R20_LOAD_DIR=~/r20load PEER_LOG=~/peer-r20.log sh tools/r20/capture.sh OUT [en2]
set -eu
HERE=$(CDPATH= cd "$(dirname "$0")" && pwd)
OUT=${1:?new output directory required}
IFACE=${2:-en2}
LOAD=${R20_LOAD_DIR:-$HOME/r20load}
PEER_LOG=${PEER_LOG:-$HOME/peer-r20.log}
if [ -d "$OUT" ] && [ -n "$(ls -A "$OUT")" ]; then
    echo "FAIL: output directory must be new or empty: $OUT" >&2; exit 1
fi
for name in token.txt batch.txt load.txt client.log netstat-before.txt netstat-after.txt; do
    [ -s "$LOAD/$name" ] || { echo "FAIL: missing current load input $LOAD/$name" >&2; exit 1; }
done
[ -s "$PEER_LOG" ] || { echo 'FAIL: copy current peer log to Mac and set PEER_LOG' >&2; exit 1; }
mkdir -p "$OUT"
ioreg -l -w0 -p IOService > "$OUT/props.raw.txt"
ioreg -l -w0 -r -c org_maz1_AMDMapperProbe > "$OUT/props.txt"
ioreg -l -w0 -r -c RTL8125 > "$OUT/driver-obs.txt"
[ -s "$OUT/props.txt" ] || { echo 'FAIL: probe node missing' >&2; exit 1; }
python3 "$HERE/../r11/extract_snapshot.py" "$OUT"
python3 "$HERE/../r14/extract_rxset.py" "$OUT"
mkdir -p "$OUT/r20-load"
for f in "$LOAD"/*; do
    [ ! -f "$f" ] || cp -p "$f" "$OUT/r20-load/"
done
for name in token.txt batch.txt load.txt client.log netstat-before.txt netstat-after.txt launchd.out launchd.err; do
    [ ! -f "$LOAD/$name" ] || cp -p "$LOAD/$name" "$OUT/$name"
done
cp -p "$PEER_LOG" "$OUT/peer.log"
{
    echo "round20_capture_interface : $IFACE"
    echo "round20_load_source : $LOAD"
    echo "round20_peer_source : $PEER_LOG"
    echo "captured_utc : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo '# actual loaded kext identity (read-only)'
    kmutil showloaded --list-only 2>/dev/null | grep -E 'RTL812|AMDMapperProbe' || true
} > "$OUT/r20-version-confirmation.txt"
{
    echo "kernel_release    : $(uname -r)"
    echo "kernel_version    : $(uname -v)"
    echo "kernel_arch       : $(uname -m)"
    echo "kern.uuid         : $(sysctl -n kern.uuid)"
    echo "kern.boottime     : $(sysctl -n kern.boottime)"
    echo "hostname          : $(hostname)"
    echo "date_utc          : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    for k in RTL812xLucy AMDMapperProbe; do
        b="/Library/Extensions/$k.kext/Contents/MacOS/$k"
        if [ -f "$b" ]; then
            echo "${k}_uuid      : $(xcrun dwarfdump --uuid "$b" | awk '{print $2}' | head -1)"
            echo "${k}_sha256    : $(shasum -a 256 "$b" | awk '{print $1}')"
            echo "${k}_version   : $(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "/Library/Extensions/$k.kext/Contents/Info.plist")"
        fi
    done
} > "$OUT/system.txt"
{
    ifconfig "$IFACE"
    route -n get default
    peer=$(awk '/^load_peer /{print $3}' "$OUT/load.txt" | cut -d: -f1)
    [ -z "$peer" ] || route -n get "$peer"
    netstat -rn -f inet
} > "$OUT/network.txt" 2>&1
sudo -n dmesg 2>/dev/null | tail -600 > "$OUT/dmesg.txt" || true
python3 "$HERE/capture-archive.py" "$OUT" "$IFACE"
echo "== Round20 capture complete: $OUT =="
