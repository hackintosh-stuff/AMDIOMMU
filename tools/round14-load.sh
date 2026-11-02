#!/bin/sh
# round12-load.sh -- the controlled UDP batch, run ON THE MAC as a launchd job.
#
# WHY LAUNCHD AND NOT SSH
# -----------------------
# The probe's measurement window opens tens of seconds after boot and runs for
# about 3 s. SSH is not reachable until well after that, so a load started over
# SSH can never cover the window.
#
# WHY THE SCHEDULE IS RELATIVE TO BOOT, ON THE MACH CLOCK
# ------------------------------------------------------
# Round 9 waited "until the interface is up" (~4 s after boot) while the window
# opened at 37.0 s, so the whole transfer finished 24 s BEFORE the window.
# Round 10 then discovered that `date +%s` minus `kern.boottime` is WALL-clock
# seconds since boot, while the driver stamps records with mach_absolute_time,
# and on this machine the two differ by 6-8 s. A load scheduled at "37 s" by
# wall clock produced records at 43.4 s mach time.
#
# Everything below therefore waits on CLOCK_UPTIME_RAW, which IS
# mach_absolute_time on this host, and publishes the value it used so the
# overlap can be checked numerically instead of hoped for.
#
# WHY THE TOKEN AND BATCH COME FROM FILES
# ---------------------------------------
# deploy-r12.sh writes ~/r14load/token.txt and batch.txt and puts the same two
# values in the boot-arg. The probe reads them from the boot-arg; this script
# reads them from the files. Two channels, one source: a mismatch is a
# deployment error that shows up immediately rather than as a batch that
# mysteriously does not complete.
#
# Usage: round11-load.sh <outdir> <iface> <peer-ip> <port> [start-after-boot]
set -eu

OUT=${1:?outdir}
IFACE=${2:?interface}
PEER=${3:?peer ip}
PORT=${4:?port}
START_AT=${5:-38}

mkdir -p "$OUT"

# WHERE THE DECLARATION FILES LIVE
# --------------------------------
# launchd does NOT set HOME for a daemon. With `set -u`, `$HOME/r14load/...` is
# an unbound-variable error and the whole load script dies immediately -- which
# is exactly what the first round-11 attempt did:
#
#     round11-load.sh: line 41: HOME: unbound variable
#
# and the run produced no load.txt and no client.log at all, so the capture
# would have had nothing to analyse. Falling back to the invoking user's home
# is correct here because this job runs as that user and deploy-r11.sh wrote
# the files there. If the fallback is also empty the script says so, rather
# than failing on an unset variable with a message that says nothing about the
# experiment.
#
# WHY NOT `eval echo ~$(id -un)`
# ------------------------------
# The launchd job runs as root, so `id -un` is `root` and the fallback resolved
# to /var/root -- which has no r14load directory. The first attempt after the
# boot-arg was fixed therefore reported NO-TOKEN-DECLARED even though the files
# existed at /Users/ling/r14load. The home must come from the OUT directory's
# owner, which is the user this run belongs to, not from the effective user.
if [ -z "${HOME:-}" ]; then
    OWNER=$(stat -f %Su "$(dirname "$OUT")" 2>/dev/null)
    if [ -n "$OWNER" ] && [ "$OWNER" != "root" ]; then
        HOME=$(eval echo "~$OWNER")
    fi
    export HOME
fi
[ -n "${HOME:-}" ] || { echo "load_result NO-HOME" >> "$OUT/load.txt"; exit 1; }

# Look in the job's home first, then in the out directory's owner's home. The
# second is what actually resolves under launchd-as-root, and trying both makes
# the script independent of which user it happens to run as.
find_decl() {
    _name=$1
    for _p in "$HOME/r14load/$_name" \
              "$(stat -f %Su "$(dirname "$OUT")" 2>/dev/null | sed 's|^|/Users/|')/r14load/$_name"; do
        [ -r "$_p" ] && { cat "$_p"; return 0; }
    done
    return 1
}
TOKEN=$(find_decl token.txt 2>/dev/null || echo '')
BATCH=$(find_decl batch.txt 2>/dev/null || echo '')
[ -n "$TOKEN" ] || { echo "load_result NO-TOKEN-DECLARED" >> "$OUT/load.txt"; exit 1; }
[ -n "$BATCH" ] || { echo "load_result NO-BATCH-DECLARED" >> "$OUT/load.txt"; exit 1; }

# ---- boot instant (wall clock, for the record only) ---------------------
#
# `sysctl -n kern.boottime` prints:
#     { sec = 1793465768, usec = 818395 } Sat Oct 31 09:56:08 2026
#
# A `sed 's/.*sec = \([0-9]*\).*/\1/'` extracts the USEC value, because
# "usec = " also ends in "sec = " and `.*` is greedy. Round 9's first run did
# exactly that: BOOT came out as 818395 and every wait was already satisfied.
BOOT=$(sysctl -n kern.boottime |
       awk -F'[{,}]' '{for (i=1;i<=NF;i++) if ($i ~ /sec = / && $i !~ /usec/) {gsub(/[^0-9]/,"",$i); print $i; exit}}')
case "$BOOT" in
    ''|*[!0-9]*) echo "load_result CANNOT-READ-BOOTTIME" >> "$OUT/load.txt"; exit 1 ;;
esac

MACH_NOW_NS() {
    python3 -c 'import time; print(time.clock_gettime_ns(time.CLOCK_UPTIME_RAW))'
}

{
    echo "load_boot_epoch     : $BOOT"
    echo "load_start_at_s     : $START_AT"
    echo "load_iface          : $IFACE"
    echo "load_peer           : $PEER:$PORT"
    echo "load_run_token      : $TOKEN"
    echo "load_requests       : $BATCH"
    echo "load_declared_from  : ~/r14load/{token,batch}.txt (same values as the boot-arg)"
} > "$OUT/load.txt"

# ---- 1. wait for the interface to be usable, BEFORE the schedule --------
#
# Round 10 waited on the schedule first and then on the interface, which meant
# a slow DHCP could consume the window. Waiting on the interface first, with
# its own bound, then sleeping until the target instant, is the order that
# cannot silently miss the window.
i=0
while [ "$i" -lt 90 ]; do
    if ifconfig "$IFACE" 2>/dev/null | grep -q "inet " &&
       ifconfig "$IFACE" 2>/dev/null | grep -q "status: active"; then
        break
    fi
    i=$((i + 1))
    sleep 1
done
echo "load_iface_wait_s   : $i" >> "$OUT/load.txt"

LOCAL=$(ifconfig "$IFACE" 2>/dev/null | awk '/inet /{print $2; exit}')
if [ -z "$LOCAL" ]; then
    echo "load_result NO-ADDRESS" >> "$OUT/load.txt"
    exit 1
fi

# ---- 2. the interface must be the one the route leaves by --------------
#
# This is the check round 9 lacked. Without it, a bind on the wrong interface
# looks exactly like a successful controlled transfer.
ROUTE_IF=$(route -n get "$PEER" 2>/dev/null | awk '/interface:/{print $2; exit}')
echo "load_route_interface : ${ROUTE_IF:-unknown}" >> "$OUT/load.txt"
if [ "$ROUTE_IF" != "$IFACE" ]; then
    echo "load_result FAIL-ROUTE-VIA-${ROUTE_IF:-unknown}-NOT-$IFACE" >> "$OUT/load.txt"
    exit 1
fi
MAC=$(ifconfig "$IFACE" 2>/dev/null | awk '/ether /{print $2; exit}')
echo "load_mac            : ${MAC:-unknown}" >> "$OUT/load.txt"
echo "load_local          : $LOCAL" >> "$OUT/load.txt"

# ---- 3. sleep until the target instant on the MACH clock ---------------
TARGET_NS=$((START_AT * 1000000000))
CUR_NS=$(MACH_NOW_NS)
echo "load_mach_now_ns    : $CUR_NS" >> "$OUT/load.txt"
echo "load_mach_target_ns : $TARGET_NS" >> "$OUT/load.txt"
if [ "$CUR_NS" -lt "$TARGET_NS" ]; then
    # Bounded steps with a re-read, so a slow boot cannot make the wait
    # overshoot the window.
    while : ; do
        CUR_NS=$(MACH_NOW_NS)
        [ "$CUR_NS" -lt "$TARGET_NS" ] || break
        REMAIN_MS=$(( (TARGET_NS - CUR_NS) / 1000000 ))
        [ "$REMAIN_MS" -gt 0 ] || break
        if [ "$REMAIN_MS" -gt 100 ]; then STEP_MS=100; else STEP_MS=$REMAIN_MS; fi
        python3 -c "import time; time.sleep($STEP_MS / 1000.0)"
    done
else
    # Already past the instant. Say so rather than pretending the load was on
    # time: a late load is a run whose window was missed.
    echo "load_late_by_ms     : $(( (CUR_NS - TARGET_NS) / 1000000 ))" >> "$OUT/load.txt"
fi
echo "load_mach_at_start_ns: $(MACH_NOW_NS)" >> "$OUT/load.txt"
echo "load_ready_utc      : $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUT/load.txt"

# ---- 4. the interface's own counters, before ---------------------------
netstat -I "$IFACE" -b > "$OUT/netstat-before.txt" 2>/dev/null || true

# ---- 5. the controlled batch -------------------------------------------
#
# A small, fixed number of requests, each carrying the SAME run token and a
# DISTINCT request id. The peer echoes the payload verbatim, so the reply
# carries the same identifiers back and the driver's RX record can be joined
# to the TX record by value rather than by time.
# ROUND 11: use this round's client, not round 10's.
#
# The first attempt called round10-client.py, whose --run-token takes a DECIMAL
# int. This round's declaration is the hex string "0xa3dbba85", so argparse
# rejected it:
#
#     round10-client.py: error: argument --run-token: invalid int value
#
# and no client.log was produced at all -- the load ran, the timing was right
# (38.15 s against a 38 s target), and the experiment still had nothing to
# analyse. round11-client.py parses the token with int(x, 0), so it accepts
# both forms, and it records the token in the same hex spelling the driver will
# publish.
python3 "$(dirname "$0")/round11-client.py" \
    --iface "$IFACE" --peer "$PEER" --port "$PORT" \
    --run-token "$TOKEN" --requests "$BATCH" \
    --out "$OUT/client.log" >> "$OUT/load.txt" 2>&1 || true

# ---- 6. the interface's own counters, after ----------------------------
netstat -I "$IFACE" -b > "$OUT/netstat-after.txt" 2>/dev/null || true

echo "load_mach_end_ns    : $(MACH_NOW_NS)" >> "$OUT/load.txt"
echo "load_end_utc        : $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUT/load.txt"
echo "load_done" >> "$OUT/load.txt"
