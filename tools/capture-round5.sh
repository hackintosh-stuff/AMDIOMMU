#!/bin/sh
# capture-round5.sh -- run on the Mac to snapshot probe properties + system state.
# Usage: sh capture-round5.sh <stamp>
set -eu
STAMP="${1:?usage: capture-round5.sh <stamp>}"
D="$HOME/iommu-work/evidence/$STAMP"
mkdir -p "$D"

ioreg -l -w0 -c org_maz1_AMDMapperProbe > "$D/props.txt" 2>/dev/null || true

{
    echo "=== uname ==="
    uname -a
    echo "=== sw_vers ==="
    sw_vers
    echo "=== nvram boot-args ==="
    nvram boot-args 2>/dev/null || echo "(none)"
    echo "=== kext ==="
    kmutil showloaded --list-only 2>/dev/null | grep -i amdmapper || echo "(not loaded)"
    echo "=== kext binary hash ==="
    shasum -a 256 /Library/Extensions/AMDMapperProbe.kext/Contents/MacOS/AMDMapperProbe 2>/dev/null || true
    echo "=== kext uuid ==="
    xcrun dwarfdump --uuid /Library/Extensions/AMDMapperProbe.kext/Contents/MacOS/AMDMapperProbe 2>/dev/null || true
    echo "=== en2 counters ==="
    netstat -i -b | grep -E '^en2 ' || echo "(no en2)"
    echo "=== en2 detail ==="
    ifconfig en2 2>/dev/null || true
    echo "=== panic count ==="
    ls /Library/Logs/DiagnosticReports/*.panic 2>/dev/null | wc -l
    echo "=== route ==="
    route -n get default 2>/dev/null | grep interface || true
} > "$D/system.txt" 2>&1

echo "props  : $(wc -c < "$D/props.txt") bytes"
echo "system : $(wc -c < "$D/system.txt") bytes"
echo "dir    : $D"
