#!/bin/sh
# capture-round10.sh -- put every raw input of one round-10 run in one place.
#
# RUN ON THE MAC, after the load has finished and before any reboot.
#
# WHAT IS COLLECTED, AND WHY EACH ONE IS NEEDED
# ---------------------------------------------
#   props.txt        the probe's full IORegistry properties, unmodified. This
#                    is the ONLY source for the driver snapshot the probe
#                    actually consumed -- the snapshot is an OSData property,
#                    and re-reading ioreg later would give a DIFFERENT
#                    publication (round 9's archive has two, 87 s apart).
#   driver-obs.txt   a second, later ioreg dump of the driver node. Kept for
#                    cross-checking, but it is NOT the runtime snapshot and the
#                    manifest says so.
#   client.log       the Mac side: what was sent, from which address, to which
#                    peer, with which token/request id.
#   peer.log         the peer side: what arrived and was echoed.
#   load.txt         the boot-relative schedule and the interface decision.
#   network.txt      the interface/BDF/MAC inventory AT CAPTURE TIME.
#   netstat-*.txt    the interface's own counters, before and after.
#   system.txt       kernel, boot instant, boot-args, both kext identities.
#   dmesg.txt        the kernel log, for panics or driver complaints.
set -eu

OUT=${1:?outdir}
IFACE=${2:-en2}
mkdir -p "$OUT"

echo "== capturing to $OUT =="

# ---- 1. the probe's properties, unmodified ------------------------------
#
# The probe's IOClass is `org_example_AMDMapperProbe` (the C++ class name), NOT
# `AMDMapperProbe` (the bundle name). Using the bundle name here silently
# produced a ZERO-BYTE props.txt on the first capture attempt, and a zero-byte
# file is exactly the kind of "the layer said success, the evidence is empty"
# failure this round is supposed to stop producing. The size is asserted below.
ioreg -l -w0 -p IOService > "$OUT/props.raw.txt" 2>/dev/null || true
ioreg -l -w0 -r -c org_example_AMDMapperProbe > "$OUT/props.txt" 2>/dev/null || true
if [ ! -s "$OUT/props.txt" ]; then
    echo "FAIL: props.txt is empty -- the probe node was not matched" >&2
    echo "      (expected IOClass org_example_AMDMapperProbe)" >&2
    exit 1
fi

# ---- 2. the driver node, for cross-checking ----------------------------
#
# NOTE: this is a LATER publication than the one the probe consumed. It is kept
# for cross-checking only, and the manifest says so. Round 9 archived a
# snapshot 87 s newer than the runtime one and then quoted it as if it were the
# runtime one; the distinction is recorded here explicitly.
ioreg -l -w0 -r -c RTL8125 > "$OUT/driver-obs.txt" 2>/dev/null || true

# ---- 3. the load's own records -----------------------------------------
cp -p "$HOME/r10load/load.txt"   "$OUT/load.txt"   2>/dev/null || true
cp -p "$HOME/r10load/client.log" "$OUT/client.log" 2>/dev/null || true
cp -p "$HOME/r10load/netstat-before.txt" "$OUT/" 2>/dev/null || true
cp -p "$HOME/r10load/netstat-after.txt"  "$OUT/" 2>/dev/null || true
cp -p "$HOME/r10load/launchd.out" "$OUT/" 2>/dev/null || true
cp -p "$HOME/r10load/launchd.err" "$OUT/" 2>/dev/null || true

# ---- 4. the interface / device inventory at capture time ----------------
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
    echo "# route to the peer"
    PEER=$(awk '/load_peer/{print $3}' "$OUT/load.txt" 2>/dev/null | cut -d: -f1)
    [ -n "$PEER" ] && route -n get "$PEER" 2>/dev/null | sed -n '1,20p'
    echo
    echo "# RTL8125 driver node identity"
    ioreg -r -c RTL8125 -d 3 2>/dev/null |
        grep -E 'IOMACAddress|IOInterfaceUnit|"reg"|IOClass|IOPCIPrimaryMatch|"model"' |
        head -20
} > "$OUT/network.txt" 2>/dev/null || true

# ---- 5. system identity -------------------------------------------------
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

# ---- 6. the kernel log --------------------------------------------------
sudo dmesg 2>/dev/null | tail -400 > "$OUT/dmesg.txt" || true

# ---- 7. the peer log, if it was already copied in ----------------------
# (the peer runs on Windows; its log is copied in from there)

# ---- 8. a manifest with every hash -------------------------------------
{
    echo "run_id        : $(basename "$OUT")"
    echo "captured_utc  : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "captured_local: $(date +%Y-%m-%dT%H:%M:%S%z)"
    echo "interface     : $IFACE"
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
