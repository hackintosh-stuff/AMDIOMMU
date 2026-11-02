#!/bin/sh
# round9-load.sh -- the controlled transfer, run ON THE MAC, as a launchd job.
#
# WHY LAUNCHD AND NOT SSH
# -----------------------
# The probe's measurement window opens tens of seconds after boot and runs for
# about 3 s. SSH is not reachable until well after that, so a load started over
# SSH can never cover the window. Round 8 established this the hard way: its
# first attempts produced windows with no traffic at all.
#
# WHY THE SCHEDULE IS RELATIVE TO BOOT, NOT TO JOB START
# -----------------------------------------------------
# Round 9's first attempt waited "until the interface is up", which on this
# machine is ~4 s after boot. The probe's window opened at 37.0 s. The whole
# transfer therefore finished 24 s BEFORE the window, and the run had nothing
# to show even though every layer reported success. "The load ran" and "the
# load overlapped the window" are different statements.
#
# So this script:
#   1. reads the actual boot instant (kern.boottime),
#   2. waits until a configured offset AFTER BOOT,
#   3. then keeps the transfer running for a configured DURATION that covers
#      the window from before it opens to after it closes.
#
# The offsets are parameters because the probe's schedule is a property of the
# probe, not a constant of the universe: if the probe's delay changes, these
# must change with it. Both are recorded in load.txt so the overlap can be
# checked afterwards rather than assumed.
#
# Usage:
#   round9-load.sh <outdir> <iface> <peer-ip> <port> <start-after-boot> \
#                  <seconds> [iface-wait]
set -eu

OUT=${1:?outdir}
IFACE=${2:?interface}
PEER=${3:?peer ip}
PORT=${4:?port}
START_AT=${5:?seconds after boot to start}
DURATION=${6:?seconds of traffic}
IFACE_WAIT=${7:-60}

mkdir -p "$OUT"

# ---- boot instant -------------------------------------------------------
# `sysctl -n kern.boottime` prints:
#     { sec = 1793465768, usec = 818395 } Sat Oct 31 09:56:08 2026
#
# A `sed 's/.*sec = \([0-9]*\).*/\1/'` on that string extracts the USEC value,
# because "usec = " also ends in "sec = " and `.*` is greedy. Round 9's first
# run did exactly that: BOOT came out as 818395, SINCE_BOOT as ~1.79e9, the
# "wait until 30 s after boot" test was already satisfied, and the transfer ran
# and finished 40 s before the probe's window opened. Extract the field that
# follows "{ sec = " explicitly.
BOOT=$(sysctl -n kern.boottime |
       awk -F'[{,}]' '{for (i=1;i<=NF;i++) if ($i ~ /sec = / && $i !~ /usec/) {gsub(/[^0-9]/,"",$i); print $i; exit}}')
case "$BOOT" in
    ''|*[!0-9]*) echo "load_result CANNOT-READ-BOOTTIME" >> "$OUT/load.txt"; exit 1 ;;
esac
NOW=$(date +%s)
SINCE_BOOT=$((NOW - BOOT))
[ "$SINCE_BOOT" -ge 0 ] || SINCE_BOOT=0

{
    echo "load_boot_epoch     : $BOOT"
    echo "load_start_epoch    : $NOW"
    echo "load_since_boot_s   : $SINCE_BOOT"
    echo "load_start_at_s     : $START_AT"
    echo "load_duration_s     : $DURATION"
    echo "load_iface          : $IFACE"
    echo "load_peer           : $PEER:$PORT"
} > "$OUT/load.txt"

# ---- 1. wait until the configured offset after boot ---------------------
if [ "$SINCE_BOOT" -lt "$START_AT" ]; then
    SLEEP=$((START_AT - SINCE_BOOT))
    echo "load_wait_s         : $SLEEP" >> "$OUT/load.txt"
    sleep "$SLEEP"
fi

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
NOW=$(date +%s)
echo "load_local          : $LOCAL" >> "$OUT/load.txt"
echo "load_actual_start_s : $((NOW - BOOT))" >> "$OUT/load.txt"
echo "load_ready_utc      : $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUT/load.txt"

# ---- 3. the interface's own counters, before ---------------------------
netstat -I "$IFACE" -b > "$OUT/netstat-before.txt" 2>/dev/null || true

# ---- 4. the controlled transfer ---------------------------------------
python3 "$(dirname "$0")/round9-client.py" \
    "$OUT/client.log" "$PEER" "$LOCAL" "$PORT" "$DURATION" \
    >> "$OUT/load.txt" 2>&1 || true

# ---- 5. the interface's own counters, after ----------------------------
netstat -I "$IFACE" -b > "$OUT/netstat-after.txt" 2>/dev/null || true

NOW=$(date +%s)
echo "load_actual_end_s   : $((NOW - BOOT))" >> "$OUT/load.txt"
echo "load_end_utc        : $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUT/load.txt"
echo "load_done" >> "$OUT/load.txt"
