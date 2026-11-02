#!/bin/sh
# round10-load.sh -- the controlled UDP batch, run ON THE MAC as a launchd job.
#
# WHY LAUNCHD AND NOT SSH
# -----------------------
# The probe's measurement window opens tens of seconds after boot and runs for
# about 3 s. SSH is not reachable until well after that, so a load started over
# SSH can never cover the window.
#
# WHY THE SCHEDULE IS RELATIVE TO BOOT
# ------------------------------------
# Round 9's first attempt waited "until the interface is up" (~4 s after boot)
# while the window opened at 37.0 s, so the whole transfer finished 24 s BEFORE
# the window and the run had nothing to show. "The load ran" and "the load
# overlapped the window" are different statements.
#
# WHY THIS ROUND ADDS AN INTERFACE CHECK
# --------------------------------------
# Round 9 bound a source address on en0 and called the result "the controlled
# chain", but the device under observation was en2. The transfer never touched
# the device being measured. This script therefore REFUSES to run unless the
# requested interface is the one the route to the peer actually leaves by, and
# records that decision in load.txt so it can be re-checked afterwards.
#
# Usage:
#   round10-load.sh <outdir> <iface> <peer-ip> <port> <run-token> \
#                   <requests> <start-after-boot> [iface-wait]
set -eu

OUT=${1:?outdir}
IFACE=${2:?interface}
PEER=${3:?peer ip}
PORT=${4:?port}
TOKEN=${5:?run token}
REQS=${6:?request count}
START_AT=${7:?seconds after boot to start}
IFACE_WAIT=${8:-90}

mkdir -p "$OUT"

# ---- boot instant -------------------------------------------------------
#
# `sysctl -n kern.boottime` prints:
#     { sec = 1793465768, usec = 818395 } Sat Oct 31 09:56:08 2026
#
# A `sed 's/.*sec = \([0-9]*\).*/\1/'` extracts the USEC value, because
# "usec = " also ends in "sec = " and `.*` is greedy. Round 9's first run did
# exactly that: BOOT came out as 818395 and every wait was already satisfied.
# Extract the field that follows "{ sec = " explicitly.
BOOT=$(sysctl -n kern.boottime |
       awk -F'[{,}]' '{for (i=1;i<=NF;i++) if ($i ~ /sec = / && $i !~ /usec/) {gsub(/[^0-9]/,"",$i); print $i; exit}}')
case "$BOOT" in
    ''|*[!0-9]*) echo "load_result CANNOT-READ-BOOTTIME" >> "$OUT/load.txt"; exit 1 ;;
esac
NOW=$(date +%s)
SINCE_BOOT=$((NOW - BOOT))
[ "$SINCE_BOOT" -ge 0 ] || SINCE_BOOT=0

# ---- the clock that actually matters ------------------------------------
#
# THE BUG THIS FIXES
# ------------------
# `date +%s` minus `kern.boottime` is WALL-CLOCK seconds since boot. The
# driver's records are stamped with mach_absolute_time, which on this machine
# does NOT agree with wall-clock-since-boot: a run scheduled at "37 s" by wall
# clock produced driver records at 43.4 s mach time, eight seconds later.
# Round 9's window arithmetic was done entirely in mach time and the load was
# scheduled in wall time, so the two could drift apart without anything
# looking wrong.
#
# The load must therefore be scheduled on the SAME clock the driver stamps
# with: CLOCK_UPTIME_RAW, which is mach_absolute_time. Everything below waits
# on that, and publishes it, so the overlap can be checked numerically instead
# of hoped for.
MACH_NOW_NS() {
    python3 -c 'import time; print(time.clock_gettime_ns(time.CLOCK_UPTIME_RAW))'
}
MACH_START_NS=$((START_AT * 1000000000))
CUR_NS=$(MACH_NOW_NS)
echo "load_mach_now_ns    : $CUR_NS" >> "$OUT/load.txt"
echo "load_mach_target_ns : $MACH_START_NS" >> "$OUT/load.txt"

{
    echo "load_boot_epoch     : $BOOT"
    echo "load_start_epoch    : $NOW"
    echo "load_since_boot_s   : $SINCE_BOOT"
    echo "load_start_at_s     : $START_AT"
    echo "load_iface          : $IFACE"
    echo "load_peer           : $PEER:$PORT"
    echo "load_run_token      : 0x$(printf '%08x' "$TOKEN")"
    echo "load_requests       : $REQS"
} > "$OUT/load.txt"

# ---- 1. wait until the configured offset after boot ---------------------
if [ "$CUR_NS" -lt "$MACH_START_NS" ]; then
    # Sleep in bounded steps and re-read the mach clock, so a clock adjustment
    # or a slow boot cannot make the wait overshoot the window.
    while : ; do
        CUR_NS=$(MACH_NOW_NS)
        [ "$CUR_NS" -lt "$MACH_START_NS" ] || break
        REMAIN_MS=$(( (MACH_START_NS - CUR_NS) / 1000000 ))
        [ "$REMAIN_MS" -gt 0 ] || break
        if [ "$REMAIN_MS" -gt 200 ]; then STEP_MS=200; else STEP_MS=$REMAIN_MS; fi
        python3 -c "import time; time.sleep($STEP_MS / 1000.0)"
    done
fi
echo "load_mach_at_start_ns: $(MACH_NOW_NS)" >> "$OUT/load.txt"

# ---- 2. wait for the interface to be usable -----------------------------
i=0
while [ "$i" -lt "$IFACE_WAIT" ]; do
    if ifconfig "$IFACE" 2>/dev/null | grep -q "inet " &&
       ifconfig "$IFACE" 2>/dev/null | grep -q "status: active"; then
        break
    fi
    i=$((i + 1))
    sleep 1
done

LOCAL=$(ifconfig "$IFACE" 2>/dev/null | awk '/inet /{print $2; exit}')
if [ -z "$LOCAL" ]; then
    echo "load_result NO-ADDRESS" >> "$OUT/load.txt"
    exit 1
fi

# ---- 3. the interface must be the one the route leaves by --------------
#
# This is the check round 9 lacked. Without it, a bind on the wrong interface
# looks exactly like a successful controlled transfer.
ROUTE_IF=$(route -n get "$PEER" 2>/dev/null | awk '/interface:/{print $2; exit}')
echo "load_route_interface : ${ROUTE_IF:-unknown}" >> "$OUT/load.txt"
if [ "$ROUTE_IF" != "$IFACE" ]; then
    echo "load_result FAIL-ROUTE-VIA-${ROUTE_IF:-unknown}-NOT-$IFACE" >> "$OUT/load.txt"
    exit 1
fi

# ---- 4. the MAC of the interface, so the device can be identified ------
MAC=$(ifconfig "$IFACE" 2>/dev/null | awk '/ether /{print $2; exit}')
echo "load_mac            : ${MAC:-unknown}" >> "$OUT/load.txt"

NOW=$(date +%s)
echo "load_local          : $LOCAL" >> "$OUT/load.txt"
echo "load_actual_start_s : $((NOW - BOOT))" >> "$OUT/load.txt"
echo "load_mach_actual_ns : $(MACH_NOW_NS)" >> "$OUT/load.txt"
echo "load_ready_utc      : $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUT/load.txt"

# ---- 5. the interface's own counters, before ---------------------------
netstat -I "$IFACE" -b > "$OUT/netstat-before.txt" 2>/dev/null || true

# ---- 6. the controlled batch -------------------------------------------
#
# A small, fixed number of requests, each carrying the SAME run token and a
# DISTINCT request id. The peer echoes the payload verbatim, so the reply
# carries the same identifiers back and the driver's RX record can be joined
# to the TX record by value rather than by time.
python3 "$(dirname "$0")/round10-client.py" \
    --iface "$IFACE" --peer "$PEER" --port "$PORT" \
    --run-token "$TOKEN" --requests "$REQS" \
    --out "$OUT/client.log" >> "$OUT/load.txt" 2>&1 || true

# ---- 7. the interface's own counters, after ----------------------------
netstat -I "$IFACE" -b > "$OUT/netstat-after.txt" 2>/dev/null || true

NOW=$(date +%s)
echo "load_actual_end_s   : $((NOW - BOOT))" >> "$OUT/load.txt"
echo "load_end_utc        : $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUT/load.txt"
echo "load_done" >> "$OUT/load.txt"
