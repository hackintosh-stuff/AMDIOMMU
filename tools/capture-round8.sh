#!/bin/sh
# capture-round8.sh — capture the round-8 evidence set with a manifest.
#
# WHY THE MANIFEST EXISTS
# -----------------------
# Round 6's report quoted a fault address and a root PA that appear nowhere in
# the capture it cited: they came from a different boot. Nothing in the
# archive made that visible, so the mistake survived review. Every round-8
# capture therefore records, in the same directory:
#
#   run_id          the directory name (UTC timestamp of capture)
#   system.txt      kernel UUID, boot time, boot-args, timezone
#   props.txt       the raw ioreg property dump (unmodified)
#   summary.txt     the analyser output
#   MANIFEST.txt    versions, UUIDs, SHA-256 of every file in the directory
#
# The manifest is written LAST, after the hashes are computed, so the hashes
# describe what is actually on disk.
set -eu

ROOT=${1:-$HOME/iommu-work}
STAMP=$(date -u +%Y%m%d-%H%M%S)
OUT="$ROOT/docs/evidence/$STAMP"
mkdir -p "$OUT"

echo "run_id: $STAMP"
echo "dir   : $OUT"

# ---- 1. system identity -------------------------------------------------
{
    echo "run_id            : $STAMP"
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
} > "$OUT/system.txt"

# ---- 2. the probe's own properties, unmodified --------------------------
ioreg -l -w0 -c org_example_AMDMapperProbe > "$OUT/props.txt" 2>/dev/null || true

# ---- 3. probe binary identity ------------------------------------------
PROBE=/Library/Extensions/AMDMapperProbe.kext
PB=""
PU=""
PS=""
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

# ---- 4. analyser output -------------------------------------------------
if [ -f "$ROOT/tools/analyze-round8.py" ] && [ -s "$OUT/props.txt" ]; then
    python3 "$ROOT/tools/analyze-round8.py" "$OUT/props.txt" \
        > "$OUT/summary.txt" 2>&1 || true
else
    echo "analyser or props.txt unavailable" > "$OUT/summary.txt"
fi

# ---- 5. manifest, written last -----------------------------------------
{
    echo "run_id        : $STAMP"
    echo "captured_utc  : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "probe_version : ${PB:-absent}"
    echo "probe_uuid    : ${PU:-absent}"
    echo "probe_sha256  : ${PS:-absent}"
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
