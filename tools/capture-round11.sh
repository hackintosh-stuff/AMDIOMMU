#!/bin/sh
# capture-round11.sh -- archive one round-11 run, including the snapshot the
# probe actually used.
#
# RUN ON THE MAC, after the load has finished and before any reboot.
#
# WHAT IS DIFFERENT FROM ROUND 10
# -------------------------------
# Round 10 captured props.raw.txt and then extracted `rtl812x-obs-snapshot`
# from it. That property is whatever the driver had published at ioreg time --
# 43 seconds after the probe finished judging. So the archived blob was not the
# snapshot the verdicts were computed from, and every downstream check was
# therefore about the wrong object.
#
# Round 11's probe exports the bytes it decoded as `m2-b2-obs-snapshot-used`
# and their sha256 as `m2-b2-obs-used-sha256`. This script:
#
#   * writes that blob to obs-snapshot-used.bin and asserts its sha256 equals
#     the probe's published value, ON THE MAC, before the archive leaves;
#   * ALSO writes the driver's own property to driver-snapshot-later.bin, so the
#     gap between the two publications is a recorded measurement rather than a
#     story;
#   * records the probe's own declaration of which publication it used.
#
# A missing export is a hard failure here. "The run looked fine but there is no
# re-checkable input" is exactly the state round 10 shipped.
set -eu

OUT=${1:?outdir}
IFACE=${2:-en2}
mkdir -p "$OUT"

echo "== capturing to $OUT =="

# ---- 1. the probe's properties, unmodified ------------------------------
#
# The probe's IOClass is `org_maz1_AMDMapperProbe` (the C++ class name), NOT
# `AMDMapperProbe` (the bundle name). Using the bundle name silently produces a
# ZERO-BYTE props.txt, which is the "the layer said success, the evidence is
# empty" failure this project keeps finding.
ioreg -l -w0 -p IOService > "$OUT/props.raw.txt" 2>/dev/null || true
ioreg -l -w0 -r -c org_maz1_AMDMapperProbe > "$OUT/props.txt" 2>/dev/null || true
if [ ! -s "$OUT/props.txt" ]; then
    echo "FAIL: props.txt is empty -- the probe node was not matched" >&2
    echo "      (expected IOClass org_maz1_AMDMapperProbe)" >&2
    exit 1
fi

# ---- 2. the snapshot the probe actually used ---------------------------
python3 "$(dirname "$0")/r11/extract_snapshot.py" "$OUT" || {
    echo "FAIL: the probe did not export a verifiable used-snapshot." >&2
    echo "      Without it this run has no re-checkable input." >&2
    exit 1; }

# ---- 3. the driver node, for cross-checking only ----------------------
#
# This is a LATER publication than the one the probe consumed. It is kept so a
# human can see how far apart they are, and the manifest says it is not
# evidence.
ioreg -l -w0 -r -c RTL8125 > "$OUT/driver-obs.txt" 2>/dev/null || true

# ---- 4. the load's own records -----------------------------------------
cp -p "$HOME/r11load/load.txt"   "$OUT/load.txt"   2>/dev/null || true
cp -p "$HOME/r11load/client.log" "$OUT/client.log" 2>/dev/null || true
cp -p "$HOME/r11load/netstat-before.txt" "$OUT/" 2>/dev/null || true
cp -p "$HOME/r11load/netstat-after.txt"  "$OUT/" 2>/dev/null || true
cp -p "$HOME/r11load/launchd.out" "$OUT/" 2>/dev/null || true
cp -p "$HOME/r11load/launchd.err" "$OUT/" 2>/dev/null || true

# ---- 5. the interface / device inventory at capture time ----------------
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
        grep -E 'IOMACAddress|IOInterfaceUnit|"reg"|IOClass|rtl812x-obs-epoch' |
        head -20
} > "$OUT/network.txt" 2>/dev/null || true

# ---- 6. system identity -------------------------------------------------
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

# ---- 7. the kernel log --------------------------------------------------
sudo dmesg 2>/dev/null | tail -400 > "$OUT/dmesg.txt" || true

# ---- 8. a manifest with every hash -------------------------------------
{
    echo "run_id        : $(basename "$OUT")"
    echo "captured_utc  : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "captured_local: $(date +%Y-%m-%dT%H:%M:%S%z)"
    echo "interface     : $IFACE"
    echo
    echo "AUTHORITATIVE DRIVER EVIDENCE: obs-snapshot-used.bin"
    echo "  These are the exact bytes the probe decoded to produce its verdicts."
    echo "  Its sha256 equals the probe's own m2-b2-obs-used-sha256, asserted"
    echo "  above before this archive was written."
    echo
    echo "NOT EVIDENCE: driver-snapshot-later.bin, driver-obs.txt"
    echo "  The driver node's state at ioreg time, which is a LATER publication"
    echo "  than the one the probe used. Round 10 analysed this one by mistake."
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
