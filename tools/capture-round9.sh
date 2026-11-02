#!/bin/sh
# capture-round9.sh -- capture the round-9 evidence set with a manifest.
#
# WHAT IS DIFFERENT FROM capture-round8.sh
# ----------------------------------------
# Round 8 captured the probe's properties and the analyser output. It did NOT
# capture the peer's log, the client's log, or the interface's own counters --
# so the claim "a controlled transfer happened" rested entirely on the probe's
# own view of its own NIC. Round 9 requires all four in the same directory with
# one manifest, because the correspondence between them is the point.
#
# The manifest is written LAST, after the hashes are computed, so the hashes
# describe what is actually on disk.
#
# Usage:
#   capture-round9.sh <root> <run-dir> [load-dir]
set -eu

ROOT=${1:-$HOME/r9root}
RUN=${2:?run directory name}
LOAD=${3:-}

OUT="$ROOT/docs/evidence/$RUN"
mkdir -p "$OUT"

echo "run_id: $RUN"
echo "dir   : $OUT"

# ---- 1. system identity -------------------------------------------------
{
    echo "run_id            : $RUN"
    echo "captured_utc      : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "captured_local    : $(date +%Y-%m-%dT%H:%M:%S%z)"
    echo "timezone          : $(readlink /etc/localtime | sed 's|.*zoneinfo/||')"
    echo "kernel_release    : $(uname -r)"
    echo "kernel_version    : $(uname -v)"
    echo "kernel_arch       : $(uname -m)"
    echo "kern.uuid         : $(sysctl -n kern.uuid)"
    echo "kern.boottime     : $(sysctl -n kern.boottime)"
    echo "hw.model          : $(sysctl -n hw.model)"
    echo "hostname          : $(hostname)"
    echo "boot-args(nvram)  : $(nvram boot-args 2>/dev/null | sed 's/^boot-args[[:space:]]*//')"
    echo "panic_count       : $(ls -1 /Library/Logs/DiagnosticReports/Panic* 2>/dev/null | wc -l | tr -d ' ')"
    echo "hw.tbfrequency    : $(sysctl -n hw.tbfrequency 2>/dev/null || echo unknown)"
} > "$OUT/system.txt"

# ---- 2. interface and route evidence -----------------------------------
#
# Which NIC carries the traffic is part of the claim: descriptors on the
# RTL8125 only mean something if the transfer used the RTL8125.
{
    echo "# interface inventory"
    for i in $(ifconfig -l); do
        printf '%s: ' "$i"
        ifconfig "$i" 2>/dev/null |
            awk '/inet /{printf "inet=%s ", $2} /status:/{printf "status=%s ", $2} /ether/{printf "ether=%s ", $2}'
        echo
    done
    echo
    echo "# default route"
    route -n get default 2>/dev/null || true
    echo
    echo "# RTL8125 PCI identity"
    ioreg -l -w0 -r -c IOPCIDevice 2>/dev/null |
        grep -E '"IOName" = "pci(10ec|1186)' -A2 | head -20 || true
} > "$OUT/network.txt" 2>&1

# ---- 3. the probe's own properties, unmodified --------------------------
ioreg -l -w0 -c org_example_AMDMapperProbe > "$OUT/props.txt" 2>/dev/null || true

# ---- 4. the driver's observation log, as the driver published it --------
#
# This is a COPY of what the driver put in the IORegistry. It is kept
# separately from props.txt so that "what the driver recorded" and "what the
# probe concluded" are two files, not one.
ioreg -l -w0 -c RTL8125 2>/dev/null |
    grep -E '"rtl812x-obs-' > "$OUT/driver-obs.txt" 2>/dev/null || true

# ---- 5. the controlled transfer's two logs -----------------------------
if [ -n "$LOAD" ] && [ -d "$LOAD" ]; then
    for f in client.log load.txt netstat-before.txt netstat-after.txt; do
        [ -f "$LOAD/$f" ] && cp "$LOAD/$f" "$OUT/$f"
    done
fi

# ---- 6. probe binary identity ------------------------------------------
PROBE=/Library/Extensions/AMDMapperProbe.kext
PB=""; PU=""; PS=""
if [ -d "$PROBE" ]; then
    PB=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' \
         "$PROBE/Contents/Info.plist" 2>/dev/null || echo "?")
    PU=$(xcrun dwarfdump --uuid "$PROBE/Contents/MacOS/AMDMapperProbe" \
         2>/dev/null | awk '{print $2}' | head -1)
    PS=$(shasum -a 256 "$PROBE/Contents/MacOS/AMDMapperProbe" \
         2>/dev/null | awk '{print $1}')
fi
echo "probe_version     : ${PB:-absent}" >> "$OUT/system.txt"
echo "probe_uuid        : ${PU:-absent}" >> "$OUT/system.txt"
echo "probe_sha256      : ${PS:-absent}" >> "$OUT/system.txt"

# ---- 7. the driver binary identity -------------------------------------
DRV=/Library/Extensions/RTL812xLucy.kext
DB=""; DU=""; DS=""
if [ -d "$DRV" ]; then
    DB=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' \
         "$DRV/Contents/Info.plist" 2>/dev/null || echo "?")
    DU=$(xcrun dwarfdump --uuid "$DRV/Contents/MacOS/RTL812xLucy" \
         2>/dev/null | awk '{print $2}' | head -1)
    DS=$(shasum -a 256 "$DRV/Contents/MacOS/RTL812xLucy" \
         2>/dev/null | awk '{print $1}')
fi
echo "driver_version    : ${DB:-absent}" >> "$OUT/system.txt"
echo "driver_uuid       : ${DU:-absent}" >> "$OUT/system.txt"
echo "driver_sha256     : ${DS:-absent}" >> "$OUT/system.txt"

# ---- 8. analyser output -------------------------------------------------
if [ -f "$ROOT/tools/analyze-round9.py" ] && [ -s "$OUT/props.txt" ]; then
    python3 "$ROOT/tools/analyze-round9.py" "$OUT/props.txt" \
        > "$OUT/summary.txt" 2>&1 || true
else
    echo "analyser or props.txt unavailable" > "$OUT/summary.txt"
fi

# ---- 9. manifest, written last -----------------------------------------
{
    echo "run_id        : $RUN"
    echo "captured_utc  : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "probe_version : ${PB:-absent}"
    echo "probe_uuid    : ${PU:-absent}"
    echo "probe_sha256  : ${PS:-absent}"
    echo "driver_version: ${DB:-absent}"
    echo "driver_uuid   : ${DU:-absent}"
    echo "driver_sha256 : ${DS:-absent}"
    echo "kernel_uuid   : $(sysctl -n kern.uuid)"
    echo ""
    echo "files (sha256, size, name):"
    ( cd "$OUT" && for f in *; do
        [ "$f" = "MANIFEST.txt" ] && continue
        printf '  %s  %10s  %s\n' \
            "$(shasum -a 256 "$f" | awk '{print $1}')" \
            "$(wc -c < "$f" | tr -d ' ')" "$f"
      done )
} > "$OUT/MANIFEST.txt"

echo "---"
echo "manifest:"
cat "$OUT/MANIFEST.txt"
