#!/bin/sh
# round23-load.sh -- wait for the target NIC, then run the load.
#
# ROUND 23: WITH THE USB NIC DISABLED THIS IS ALMOST A NO-OP, AND THAT IS THE
# POINT. The USB NIC (en0, 192.168.50.204) shares 192.168.50.0/24 with en2 (the
# RTL8127 under test). While both were up macOS installed a /24 route via en0 and
# pinned a PERMANENT ARP entry for the peer on en2 pointing at en2's OWN MAC, so
# every packet to the peer resolved to the local NIC and looped back. Four boots
# went to that: the route looked right, the authorization was fresh, and the seed
# still timed out.
#
# The fix is not a route hack -- it is removing the second interface from the
# subnet, which round 23 does for the whole round. What remains here is only the
# BOOT-ORDER wait: launchd starts this job before en2 has an IPv4 address, and a
# route/ARP decision taken then is meaningless.
#
# NO `sudo`: launchd runs this as root, and sudo without a tty fails silently.
set -eu
PEER=${PEER:-192.168.50.122}
IFACE=${IFACE:-en2}
LOAD=${LOAD:-/Users/ling/r12work/tools/r21/load.py}
OUT=${OUT:-/Users/ling/r21load}
WAIT=${WAIT:-120}

# 1. The target NIC must have its address before any of this means anything.
n=0
while [ "$n" -lt "$WAIT" ]; do
    /sbin/ifconfig "$IFACE" 2>/dev/null | /usr/bin/grep -q 'inet ' && break
    n=$((n + 1)); sleep 1
done
if ! /sbin/ifconfig "$IFACE" 2>/dev/null | /usr/bin/grep -q 'inet '; then
    echo "round23-load: $IFACE never got an IPv4 address in ${WAIT}s" >&2
    /sbin/ifconfig "$IFACE" >&2 2>&1 || true
    exit 3
fi

# 2. The peer must route through the NIC under test. This is not a workaround:
#    it is the property the experiment is built on, and load.py refuses without
#    it. Failing here names the real cause instead of surfacing later as
#    "no fresh authorization".
got=$(/sbin/route -n get "$PEER" 2>/dev/null | /usr/bin/awk '/interface:/{print $2}')
if [ "$got" != "$IFACE" ]; then
    echo "round23-load: peer route is on ${got:-none}, not $IFACE;" \
         "is the USB NIC still enabled?" >&2
    /sbin/route -n get "$PEER" >&2 2>&1 || true
    exit 3
fi

exec /usr/bin/python3 "$LOAD" "$OUT"