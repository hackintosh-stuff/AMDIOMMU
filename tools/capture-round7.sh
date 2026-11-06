#!/bin/sh
# Capture round-7 evidence from the live probe into a timestamped directory.
#
# Usage (on the Mac):
#   sh tools/capture-round7.sh
#
# Writes docs/evidence/<stamp>/{props.txt,system.txt,summary.txt}
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
STAMP=$(date +%Y%m%d-%H%M%S)
OUT="$ROOT/docs/evidence/$STAMP"
mkdir -p "$OUT"

echo "capturing to $OUT"

ioreg -l -w0 -c org_maz1_AMDMapperProbe > "$OUT/props.txt" 2>/dev/null || true
ioreg -l -w0 -c org_maz1_AMDMapperProbe > "$OUT/props.txt" 2>/dev/null || true

{
    echo "=== uname ==="
    uname -a
    echo "=== sw_vers ==="
    sw_vers
    echo "=== boot-args ==="
    sudo nvram boot-args 2>/dev/null | head -1
    echo "=== kext ==="
    kmutil showloaded 2>/dev/null | grep -i AMDMapperProbe || echo "not loaded"
    echo "=== sha ==="
    shasum -a 256 /Library/Extensions/AMDMapperProbe.kext/Contents/MacOS/AMDMapperProbe 2>/dev/null || true
    echo "=== uuid ==="
    xcrun dwarfdump --uuid /Library/Extensions/AMDMapperProbe.kext/Contents/MacOS/AMDMapperProbe 2>/dev/null || true
    echo "=== kernel uuid ==="
    sysctl -n kern.uuid
    echo "=== panics ==="
    ls -1 /Library/Logs/DiagnosticReports/*.panic 2>/dev/null | wc -l
    echo "=== en2 ==="
    ifconfig en2 2>/dev/null | grep -E "inet |media|status" || echo "no en2"
    echo "=== route ==="
    route -n get default 2>/dev/null | grep interface
    echo "=== linkno ==="
    netstat -ibn 2>/dev/null | awk '/^en2/ {print $1; exit}'
    echo "=== hw.model ==="
    sysctl -n hw.model
    echo "=== memory ==="
    sysctl -n hw.memsize
} > "$OUT/system.txt" 2>&1

# A short, readable summary of the round-7 fields only.
grep -E '"m2-b2-' "$OUT/props.txt" 2>/dev/null \
    | sed -E 's/^[^"]*//' | sort > "$OUT/summary.txt" || true

echo "files:"
ls -l "$OUT"
echo
echo "verdict/stage:"
grep -E '"(m2-b2-verdict|m2-b2-stage|m2-b2-mode)"' "$OUT/summary.txt" || true
echo
echo "OUT=$OUT"
