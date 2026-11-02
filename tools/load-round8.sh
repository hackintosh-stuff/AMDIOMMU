#!/bin/sh
# load-round8.sh — controlled TX load for the round-8 experiment.
#
# WHY A SCRIPT RATHER THAN A ONE-LINER
# ------------------------------------
# The probe's measurement window opens ~20 s after boot and lasts 3 s. The
# load has to be running across that whole interval, and it has to produce
# NEW descriptor submissions (not just retransmits of a cached route), so the
# window's [tailBefore, tailAfter) range is non-empty.
#
# The load is deliberately simple and self-evidencing:
#   * ICMP echo to the gateway: every packet is a fresh mbuf, so every one is
#     a new descriptor submission;
#   * a UDP stream to a peer that may or may not answer: UDP still submits
#     descriptors for the outbound datagrams, which is what TX measures;
#   * a TCP connect attempt: exercises the TSO/GSO path when the segment is
#     large enough, which is where the length field stops being a length.
#
# Everything is logged with timestamps so the load can be correlated with the
# probe's own monotonic timestamps and wall-clock window edges.
set -u

OUT=${1:-$HOME/round8-load.log}
DUR=${2:-90}
PEER=192.168.50.122
GW=192.168.50.1

: > "$OUT"
log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$OUT"; }

log "load start dur=${DUR}s peer=$PEER gw=$GW"
log "ifconfig: $(ifconfig en0 2>/dev/null | awk '/inet /{print $2}')"

# Baseline counters, so the load's own effect is measurable.
log "netstat-before: $(netstat -I en0 -b 2>/dev/null | tail -1)"

END=$(( $(date +%s) + DUR ))
N=0
while [ "$(date +%s)" -lt "$END" ]; do
    N=$((N + 1))
    # 1. ICMP: one new mbuf per echo, so one new descriptor submission each.
    ping -c 1 -W 1000 -s 1200 "$GW" >/dev/null 2>&1
    # 2. UDP: outbound datagrams always submit descriptors even if nobody
    #    is listening.
    printf 'round8-%s\n' "$N" | nc -u -w 0 "$PEER" 9 >/dev/null 2>&1
    # 3. TCP: a connect attempt exercises the established-data path when it
    #    succeeds; a refusal still submits the SYN descriptor.
    nc -z -G 1 "$PEER" 22 >/dev/null 2>&1
    if [ $((N % 20)) -eq 0 ]; then
        log "iter=$N netstat: $(netstat -I en0 -b 2>/dev/null | tail -1)"
    fi
done

log "load end iter=$N"
log "netstat-after: $(netstat -I en0 -b 2>/dev/null | tail -1)"
log "done"
