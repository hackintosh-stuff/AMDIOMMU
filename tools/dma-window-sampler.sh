#!/bin/sh
# dma-window-sampler.sh -- run ON THE MAC, right after boot.
#
# Purpose: externally-measured evidence that the target interface actually
# completed traffic during the probe's translation window.
#
# WHAT CHANGED FROM ROUND 5, AND WHY
# ----------------------------------
# Round 5's sampler had four problems the task called out:
#
#   1. It matched the interface by the literal string `<Link#9>`. The link
#      number is assigned at boot and can change, so a different boot could
#      silently produce an empty sample file -- which the correlator then
#      read as "counters did not move".
#   2. It pinged a hardcoded source address (192.168.60.204). If the address
#      moved, the load generator failed and again produced no signal.
#   3. It recorded only whole seconds, so a 3-second window had ~3 usable
#      points and boundary attribution was +/- 1 s.
#   4. It never recorded when the load generator actually started or stopped,
#      nor whether it errored, so "the counters moved" could not be tied to
#      the intended load.
#
# Now:
#   * the interface is selected by BSD name and its Link# is READ from
#     netstat, not assumed
#   * the source address is read from ifconfig for that interface
#   * every sample carries a millisecond timestamp, and the sampler records
#     its own start/end margins
#   * the load generator records how many echoes it actually sent and how
#     many replies came back
#   * a sidecar .meta file records interface identity, addresses, link
#     number, load outcome, and the exact sampling bounds
#
# Usage:  sh dma-window-sampler.sh <seconds> <outfile>
#         IFACE=en2   override the interface
#         LOAD=0      sample without generating load
#
# NOTE ON WHAT THIS PROVES
#   Interface counters are updated by the driver from a hardware counter
#   dump, and that dump only lands when the device has completed it
#   (statUpdateThread checks the CounterDump bit first). So a counter that
#   advances is evidence the device completed that work. It is still a
#   SECONDARY signal: the primary evidence is the TX descriptor DescOwn
#   transitions the probe reads directly. This sampler corroborates the
#   probe; it does not replace it.

set -eu

SECS="${1:-150}"
OUT="${2:-$HOME/iommu-work/dma-window.tsv}"
IFACE="${IFACE:-en2}"
SAMPLE_MS="${SAMPLE_MS:-100}"
LOAD="${LOAD:-1}"
META="${OUT%.tsv}.meta"

: > "$OUT"
: > "$META"

now_ms() {
    perl -MTime::HiRes=time -e 'printf "%d\n", time()*1000' 2>/dev/null \
        || echo $(( $(date +%s) * 1000 ))
}

# ---- discover the interface's real identity ----
linkno=$(netstat -i -b -n 2>/dev/null \
    | awk -v i="$IFACE" '$1==i && $3 ~ /^<Link#/ {gsub(/[<>]|Link#/,"",$3); print $3; exit}')
srcaddr=$(ifconfig "$IFACE" 2>/dev/null \
    | awk '/inet /{print $2; exit}')
bcast=$(ifconfig "$IFACE" 2>/dev/null \
    | awk '/inet /{for(i=1;i<=NF;i++) if($i=="broadcast"){print $(i+1); exit}}')
mtu=$(ifconfig "$IFACE" 2>/dev/null | awk '/mtu /{for(i=1;i<=NF;i++) if($i=="mtu"){print $(i+1); exit}}')

{
    printf 'iface=%s\n' "$IFACE"
    printf 'linkno=%s\n' "${linkno:-UNKNOWN}"
    printf 'srcaddr=%s\n' "${srcaddr:-NONE}"
    printf 'bcast=%s\n' "${bcast:-NONE}"
    printf 'mtu=%s\n' "${mtu:-UNKNOWN}"
    printf 'sample_ms=%s\n' "$SAMPLE_MS"
    printf 'load=%s\n' "$LOAD"
    printf 'sampler_start_ms=%s\n' "$(now_ms)"
} >> "$META"

# ---- counter reader: match on BSD name + the DISCOVERED link number ----
counters() {
    if [ -n "${linkno:-}" ]; then
        netstat -i -b -n 2>/dev/null | awk -v i="$IFACE" -v l="$linkno" \
            '$1==i && $3=="<Link#"l">" {print $5, $6, $8, $9; exit}'
    else
        netstat -i -b -n 2>/dev/null \
            | awk -v i="$IFACE" '$1==i {print $5,$6,$8,$9; exit}'
    fi
}

start=$(now_ms)
end=$((start + SECS * 1000))

printf '# iface=%s linkno=%s src=%s start_ms=%s end_ms=%s sample_ms=%s load=%s\n' \
    "$IFACE" "${linkno:-?}" "${srcaddr:-?}" "$start" "$end" "$SAMPLE_MS" \
    "$LOAD" >> "$OUT"
printf 'wall_ms\tipkts\tierrs\topkts\toerrs\n' >> "$OUT"

# ---- wait for the interface to get an IPv4 address ----
#
# At boot the LaunchDaemon starts before DHCP has run, so the address is
# often still absent. Round 5 never noticed because it was started by hand
# after login. Waiting is the correct fix: it keeps load generation inside
# the same run instead of silently skipping it.
if [ "$LOAD" = "1" ] && [ -z "${srcaddr:-}" ]; then
    waited=0
    while [ "$waited" -lt 60 ]; do
        sleep 1
        waited=$((waited + 1))
        srcaddr=$(ifconfig "$IFACE" 2>/dev/null | awk '/inet /{print $2; exit}')
        [ -n "${srcaddr:-}" ] && break
    done
    bcast=$(ifconfig "$IFACE" 2>/dev/null \
        | awk '/inet /{for(i=1;i<=NF;i++) if($i=="broadcast"){print $(i+1); exit}}')
    {
        printf 'srcaddr_after_wait=%s\n' "${srcaddr:-NONE}"
        printf 'bcast_after_wait=%s\n' "${bcast:-NONE}"
        printf 'addr_wait_s=%s\n' "$waited"
    } >> "$META"
fi

# ---- load generator: numbered echo stream, with recorded outcome ----
LOADPID=""
if [ "$LOAD" = "1" ] && [ -n "${srcaddr:-}" ]; then
    (
        sent=0
        got=0
        while [ "$(now_ms)" -lt "$end" ]; do
            res=$(ping -c 50 -i 0.02 -S "$srcaddr" "${bcast:-255.255.255.255}" \
                  2>/dev/null | awk '/packets transmitted/{print $1, $4}')
            s=$(echo "$res" | awk '{print $1}')
            g=$(echo "$res" | awk '{print $2}')
            case "$s" in ''|*[!0-9]*) s=0 ;; esac
            case "$g" in ''|*[!0-9]*) g=0 ;; esac
            sent=$((sent + s))
            got=$((got + g))
            printf '%s %s %s\n' "$(now_ms)" "$sent" "$got" >> "$META.load"
        done
        printf 'load_sent=%s\nload_received=%s\n' "$sent" "$got" >> "$META"
        printf 'load_stop_ms=%s\n' "$(now_ms)" >> "$META"
    ) &
    LOADPID=$!
    printf 'load_pid=%s\n' "$LOADPID" >> "$META"
else
    printf 'load_skipped=yes\n' >> "$META"
fi

# ---- sample until the deadline ----
while :; do
    t=$(now_ms)
    [ "$t" -ge "$end" ] && break
    c=$(counters)
    if [ -n "$c" ]; then
        printf '%s\t%s\n' "$t" "$(printf '%s' "$c" | tr ' ' '\t')" >> "$OUT"
    fi
    perl -e "select(undef,undef,undef,$SAMPLE_MS/1000)" 2>/dev/null \
        || sleep 1
done

if [ -n "$LOADPID" ]; then
    kill "$LOADPID" 2>/dev/null || true
    wait "$LOADPID" 2>/dev/null || true
fi

{
    printf 'sampler_end_ms=%s\n' "$(now_ms)"
    printf 'samples=%s\n' "$(grep -vc '^#' "$OUT" || echo 0)"
} >> "$META"

echo "sampler wrote $OUT"
echo "metadata    $META"
