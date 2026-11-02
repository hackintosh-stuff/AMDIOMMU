#!/bin/sh
# capture-round14.sh -- archive one round-14 run, including the RX post blob the
# probe actually decoded.
#
# RUN ON THE MAC, after the load has finished and before any reboot.
#
# WHAT IS DIFFERENT FROM ROUND 13
# -------------------------------
# Round 13 archived the driver observation-log snapshot the probe used. Round 14
# adds a SECOND authoritative input: `rtl812x-rxpost`, the baseline slot table
# plus the rearm log, which is what the RX set was built from.
#
# Both are exported by the probe itself (`m2-b2-obs-snapshot-used` and
# `m2-b2-rxset-raw`) together with their sha256, so the archive can be checked
# against what the probe decoded rather than against whatever the driver node
# happened to hold at ioreg time. That distinction is the round-10 defect and it
# is why both files are extracted and hashed here, on the Mac, before the
# archive leaves.
#
# A missing RX post export is a HARD FAILURE when the probe says the set was
# built: it would mean the round has a coverage claim with no re-checkable
# input, which is exactly the state round 10 shipped.
set -eu

OUT=${1:?outdir}
IFACE=${2:-en2}
mkdir -p "$OUT"

echo "== capturing to $OUT =="

# ---- 1. the probe's properties, unmodified ------------------------------
# The probe's IOClass is `org_example_AMDMapperProbe` (the C++ class name), NOT
# `AMDMapperProbe` (the bundle name): the bundle name silently produces a
# ZERO-BYTE props.txt.
ioreg -l -w0 -p IOService > "$OUT/props.raw.txt" 2>/dev/null || true
ioreg -l -w0 -r -c org_example_AMDMapperProbe > "$OUT/props.txt" 2>/dev/null || true
if [ ! -s "$OUT/props.txt" ]; then
    echo "FAIL: props.txt is empty -- the probe node was not matched" >&2
    exit 1
fi

# ---- 2. the observation-log snapshot the probe actually used -----------
python3 "$(dirname "$0")/r11/extract_snapshot.py" "$OUT" || {
    echo "FAIL: the probe did not export a verifiable used-snapshot." >&2
    exit 1; }

# ---- 3. the RX post blob the probe actually decoded --------------------
python3 "$(dirname "$0")/r14/extract_rxset.py" "$OUT" || {
    echo "FAIL: the probe did not export a verifiable rtl812x-rxpost blob." >&2
    echo "      Without it the RX set has no re-checkable input." >&2
    exit 1; }

# ---- 4. the driver node, for cross-checking only ----------------------
ioreg -l -w0 -r -c RTL8125 > "$OUT/driver-obs.txt" 2>/dev/null || true

# ---- 5. the load's own records -----------------------------------------
cp -p "$HOME/r14load/load.txt"   "$OUT/load.txt"   2>/dev/null || true
cp -p "$HOME/r14load/client.log" "$OUT/client.log" 2>/dev/null || true
cp -p "$HOME/r14load/netstat-before.txt" "$OUT/" 2>/dev/null || true
cp -p "$HOME/r14load/netstat-after.txt"  "$OUT/" 2>/dev/null || true
cp -p "$HOME/r14load/launchd.out" "$OUT/" 2>/dev/null || true
cp -p "$HOME/r14load/launchd.err" "$OUT/" 2>/dev/null || true

# ---- 5b. the peer's log ------------------------------------------------
PEER_LOG=${PEER_LOG:-$HOME/peer.log}
if [ -f "$PEER_LOG" ]; then
    cp -p "$PEER_LOG" "$OUT/peer.log"
    echo "peer log: copied from $PEER_LOG"
else
    echo "peer log: NOT FOUND at $PEER_LOG" >&2
    {
        echo "peer_log : ABSENT AT CAPTURE TIME"
        echo "  looked for: $PEER_LOG"
        echo "  The peer runs on the operator machine. Without this file the"
        echo "  analyser cannot recompute controlled_batch_complete and will"
        echo "  report the input as missing rather than assuming the exchange"
        echo "  happened."
    } > "$OUT/PEER-LOG-MISSING.txt"
fi

# ---- 6. the interface / device inventory at capture time ----------------
{
    echo "# interface inventory"
    for i in $(ifconfig -l); do
        line="$i:"
        mac=$(ifconfig "$i" 2>/dev/null | awk '/ether /{print $2; exit}')
        [ -n "$mac" ] && line="$line ether=$mac"
        ip=$(ifconfig "$i" 2>/dev/null | awk '/inet /{print $2; exit}')
        [ -n "$ip" ] && line="$line inet=$ip"
        st=$(ifconfig "$i" 2>/dev/null | awk '/status:/{print $2; exit}')
        [ -n "$st" ] && line="$line status=$st"
        echo "$line"
    done
    echo
    echo "# default route"
    route -n get default 2>/dev/null | sed -n '1,20p'
    echo
    echo "# all default routes"
    netstat -rn -f inet 2>/dev/null | awk '$1=="default"'
    echo
    echo "# route to the peer"
    PEER=$(awk '/load_peer/{print $3}' "$OUT/load.txt" 2>/dev/null | cut -d: -f1)
    [ -n "$PEER" ] && route -n get "$PEER" 2>/dev/null | sed -n '1,20p'
    echo
    echo "# RTL8125 driver node identity"
    ioreg -r -c RTL8125 -d 3 2>/dev/null |
        grep -E 'IOMACAddress|IOInterfaceUnit|"reg"|IOClass|rtl812x-obs-epoch|rtl812x-rxpost' |
        head -20
} > "$OUT/network.txt" 2>/dev/null || true

# ---- 7. system identity -------------------------------------------------
{
    echo "kernel_release    : $(uname -r)"
    echo "kernel_version    : $(uname -v)"
    echo "kernel_arch       : $(uname -m)"
    echo "kern.uuid         : $(sysctl -n kern.uuid 2>/dev/null || echo unknown)"
    echo "kern.boottime     : $(sysctl -n kern.boottime)"
    echo "hw.model          : $(sysctl -n hw.model)"
    echo "hw.tbfrequency    : $(sysctl -n hw.tbfrequency)"
    echo "hostname          : $(hostname)"
    echo "timezone          : $(systemsetup -gettimezone 2>/dev/null | cut -d: -f2 | tr -d ' ' || echo unknown)"
    echo "date_utc          : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "date_local        : $(date +%Y-%m-%dT%H:%M:%S%z)"
    echo "boot-args(nvram)  : $(nvram boot-args 2>/dev/null | sed 's/^boot-args\t//')"
    echo "panic_count       : $(ls /Library/Logs/DiagnosticReports/*.panic 2>/dev/null | wc -l | tr -d ' ')"
    for k in RTL812xLucy AMDMapperProbe; do
        b="/Library/Extensions/$k.kext/Contents/MacOS/$k"
        if [ -f "$b" ]; then
            echo "${k}_uuid      : $(xcrun dwarfdump --uuid "$b" 2>/dev/null | awk '{print $2}' | head -1)"
            echo "${k}_sha256    : $(shasum -a 256 "$b" | awk '{print $1}')"
            echo "${k}_version   : $(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "/Library/Extensions/$k.kext/Contents/Info.plist" 2>/dev/null || echo unknown)"
        fi
    done
} > "$OUT/system.txt" 2>/dev/null || true

# ---- 8. the kernel log --------------------------------------------------
sudo dmesg 2>/dev/null | tail -400 > "$OUT/dmesg.txt" || true

# ---- 9. a manifest with every hash -------------------------------------
{
    echo "run_id        : $(basename "$OUT")"
    echo "captured_utc  : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "captured_local: $(date +%Y-%m-%dT%H:%M:%S%z)"
    echo "interface     : $IFACE"
    echo
    echo "AUTHORITATIVE INPUTS (both exported by the probe itself):"
    echo "  obs-snapshot-used.bin  the driver observation-log snapshot the probe"
    echo "                         decoded; sha256 == m2-b2-obs-used-sha256"
    echo "  rxset-raw.bin          the rtl812x-rxpost blob the probe built the"
    echo "                         RX set from; sha256 == m2-b2-rxset-raw-sha256"
    echo
    echo "NOT EVIDENCE: driver-snapshot-later.bin, driver-obs.txt"
    echo "  The driver node's state at ioreg time, a LATER publication than the"
    echo "  ones the probe used."
    echo
    echo "files (sha256, size, name):"
    for f in "$OUT"/*; do
        [ -f "$f" ] || continue
        b=$(basename "$f")
        [ "$b" = "MANIFEST.txt" ] && continue
        printf '  %s  %10d  %s\n' "$(shasum -a 256 "$f" | awk '{print $1}')" \
               "$(stat -f %z "$f")" "$b"
    done
} > "$OUT/MANIFEST.txt"

echo "== captured =="
ls -la "$OUT"
