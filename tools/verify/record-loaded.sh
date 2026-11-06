#!/bin/sh
# record-loaded.sh -- record what the RUNNING KERNEL has actually loaded.
#
# WHY THIS IS A SEPARATE SCRIPT AND A SEPARATE FILE
# -------------------------------------------------
# Round 11's report presented the UUID of the file in /Library/Extensions as
# "the loaded UUID". It is not. Three facts are different and only one of them
# is a load identity:
#
#   built      what the compiler produced          (build-record.sh, artefact-identity.txt)
#   installed  what is on disk right now           (build-record.sh, installed-identity.txt)
#   loaded     what the running kernel is using    (this script)
#
# The third can only be answered after a reboot, by asking the kernel. So it is
# written into the same record directory, as its own file, and the build record
# says it is absent until this script has run. A reader then sees which of the
# three exist instead of being told that one of them is another.
#
# WHAT IT ASKS, AND WHY EACH SOURCE IS NEEDED
# -------------------------------------------
#   kmutil showloaded -a x86_64 -v   the auxiliary collection's view: which
#                                    kexts the kernel reports as loaded, with
#                                    their version and UUID
#   ioreg -l                         the live driver instance: whether the
#                                    RTL8125 personality actually matched
#   sysctl kern.boottime             the boot this observation belongs to
#   nvram boot-args                  the arguments the kernel was given
#
# ROUND 12'S TWO QUERY BUGS (kept here as the reason for the shape)
# -----------------------------------------------------------------
#   * `kmutil showloaded -a` REQUIRES an architecture argument. Without it the
#     command exits non-zero, the grep finds nothing, and the script reported
#     "<not loaded>" for two kexts that ioreg shows running. A check that
#     reports absence because IT failed.
#   * `kmutil showloaded -v` puts the UUID in the TEXT of the line, not after a
#     `uuid:` label, so searching for "uuid:" produced an empty UUID next to a
#     line that plainly contained one.
#
# ROUND 13: FOUR MORE, ALL OF THE SAME FAMILY
# -------------------------------------------
#   R1  THE FAILURE WAS NOT CAPTURED UNDER `set -e`. `SL_OUT=$(sudo kmutil ...)`
#       followed by `SL_RC=$?` is the classic trap: under `set -e` a failing
#       command substitution in an ASSIGNMENT does not abort, but if the script
#       is ever run with a shell that does abort, or if the assignment is the
#       last command, the status is lost. The status is now captured explicitly
#       with `|| rc=$?` on the same line, and `set +e` brackets the call.
#
#   R2  THE QUERY RAN UP TO THREE TIMES. The header section ran `kmutil`, then
#       the UUID loop ran it once per kext. Three separate snapshots of a live
#       system: a kext could be loaded for the first and unloaded for the third,
#       and the record would contain both answers as if they were one
#       observation. The query now runs ONCE, its output and status are written
#       to the record, and everything else parses that saved text.
#
#   R3  A FAILED QUERY WAS STILL WRITTEN AS A LOAD LINE. The UUID loop used
#       `sudo kmutil ... 2>/dev/null | grep -m1 "$name" || true`, so on failure
#       it printed `<not reported by kmutil>` -- which reads as "not loaded".
#       Now a failed query produces NO per-kext line at all; the file says
#       `query_status : FAILED` and `identity_source : UNKNOWN`, and the ioreg
#       section is labelled as the only evidence available.
#
#   R4  "QUERY FAILED" AND "NOT LOADED" ARE DIFFERENT FACTS and are now
#       different tokens. `identity_source` is one of:
#           kmutil             the kernel answered, and answered about both
#           kmutil-partial     the kernel answered, but not about both
#           ioreg-only         kmutil failed; ioreg shows the instances
#           UNKNOWN            neither source could answer
#       Only `kmutil` or `kmutil-partial` can close the identity. `ioreg-only`
#       is evidence of a RUNNING INSTANCE, not of which BINARY it is.
#
# Usage: record-loaded.sh <build-record-dir>
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
REC=${1:-}
if [ -z "$REC" ]; then
    if [ -f "$ROOT/latest-build-record.txt" ]; then
        REC=$(cat "$ROOT/latest-build-record.txt")
    else
        echo "usage: record-loaded.sh <build-record-dir>" >&2
        exit 2
    fi
fi
if [ ! -d "$REC" ]; then
    echo "FAIL: no build record at $REC" >&2
    exit 2
fi

OUT="$REC/loaded-identity.txt"
if [ -e "$OUT" ]; then
    # A load identity belongs to ONE boot. Overwriting it would let a later
    # boot's state stand in for an earlier one's, which is the same class of
    # error as analysing a later snapshot than the probe used.
    OUT="$REC/loaded-identity.$(date -u +%Y%m%dT%H%M%SZ).txt"
    echo "NOTE: a loaded-identity.txt already exists; writing $OUT" >&2
fi

# ---- R1/R2: ONE query, status captured explicitly ----------------------
#
# `set -e` does not abort on a failure inside a command substitution used in an
# assignment, so `X=$(cmd); rc=$?` silently continues with rc=0 in some shells
# and loses the status in others. `|| rc=$?` on the SAME command is the form
# that works under every shell, and `set +e` around it makes the intent
# explicit rather than accidental.
QUERY_OUT=""
QUERY_RC=0
QUERY_ERR=""
SUDO_OK=0
if sudo -n true 2>/dev/null; then
    SUDO_OK=1
    set +e
    QUERY_OUT=$(sudo kmutil showloaded -a x86_64 -v 2>"$REC/.kmutil-stderr.tmp")
    QUERY_RC=$?
    set -e
    QUERY_ERR=$(cat "$REC/.kmutil-stderr.tmp" 2>/dev/null || true)
    rm -f "$REC/.kmutil-stderr.tmp"
else
    QUERY_RC=126          # "could not ask", distinct from "asked and failed"
    QUERY_ERR="sudo requires a password"
fi

# Persist the raw query so the parsing below is reproducible from the record.
{
    echo "# the raw `kmutil showloaded -a x86_64 -v` output this record was"
    echo "# parsed from. Written once, so every derived line in"
    echo "# loaded-identity.txt comes from THE SAME observation."
    echo "query_rc : $QUERY_RC"
    echo "--- stdout ---"
    printf '%s\n' "$QUERY_OUT"
    echo "--- stderr ---"
    printf '%s\n' "$QUERY_ERR"
} > "$REC/loaded-query-raw.txt"

if [ "$QUERY_RC" -eq 0 ]; then
    QUERY_STATUS="OK"
elif [ "$QUERY_RC" -eq 126 ]; then
    QUERY_STATUS="UNKNOWN (no root)"
else
    QUERY_STATUS="FAILED (kmutil exited $QUERY_RC)"
fi

# Does the saved output mention a kext, and with which line?
query_line_for() {
    [ "$QUERY_RC" -eq 0 ] || return 1
    printf '%s\n' "$QUERY_OUT" | grep -m1 "$1"
}

# The UUID is the first UUID-shaped token on the line. `kmutil showloaded -v`
# puts it in the text, not after a `uuid:` label.
query_uuid_for() {
    printf '%s' "$1" |
        grep -oE '[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}' |
        head -1
}

query_version_for() {
    printf '%s' "$1" | sed -n 's/.*(\([0-9][0-9.]*\)).*/\1/p' | head -1
}

# ---- R4: how far did the query get? ------------------------------------
N_FOUND=0
for name in AMDMapperProbe RTL812xLucy; do
    if query_line_for "$name" >/dev/null 2>&1; then
        N_FOUND=$((N_FOUND + 1))
    fi
done
if [ "$QUERY_RC" -ne 0 ]; then
    IDENTITY_SOURCE="UNKNOWN"
    if ioreg -l 2>/dev/null | grep -q 'IOClass.*RTL8125'; then
        IDENTITY_SOURCE="ioreg-only"
    fi
elif [ "$N_FOUND" -eq 2 ]; then
    IDENTITY_SOURCE="kmutil"
elif [ "$N_FOUND" -eq 1 ]; then
    IDENTITY_SOURCE="kmutil-partial"
else
    IDENTITY_SOURCE="UNKNOWN"
fi

{
    echo "# THE LOADED IDENTITY -- what the RUNNING KERNEL reports."
    echo "#"
    echo "# This is the only one of the three that answers \"what is loaded\"."
    echo "# It belongs to one boot; the boot time below is part of the record."
    echo "#"
    echo "# ROUND 13: everything below that starts with 'kmutil_' was parsed from"
    echo "# ONE query, whose raw text and exit status are saved in"
    echo "# loaded-query-raw.txt. A failed query is NEVER written as 'not loaded'."
    echo
    echo "recorded_utc      : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "boot_time         : $(sysctl -n kern.boottime)"
    echo "kernel            : $(uname -a)"
    echo "sw_vers           : $(sw_vers -productVersion) ($(sw_vers -buildVersion))"
    echo
    echo "boot_args         : $(nvram boot-args 2>/dev/null | sed 's/^boot-args\t//' || echo '<unreadable>')"
    echo
    echo "query_status      : $QUERY_STATUS"
    echo "query_rc          : $QUERY_RC"
    echo "query_kexts_found : $N_FOUND (of 2)"
    echo "identity_source   : $IDENTITY_SOURCE"
    echo "query_raw         : loaded-query-raw.txt"
    if [ "$QUERY_RC" -ne 0 ]; then
        echo "query_error       : $QUERY_ERR"
    fi
    echo

    echo "# ---- what the kernel says is loaded ----"
    echo
    if [ "$QUERY_RC" -ne 0 ]; then
        echo "## kmutil showloaded -a x86_64 -v  -- THE QUERY FAILED"
        echo "  query_status : $QUERY_STATUS"
        echo "  kmutil said  : $QUERY_ERR"
        echo
        echo "  A FAILED QUERY IS NOT 'NOT LOADED'. Nothing below this line is"
        echo "  a statement about what is loaded; it is a statement about what"
        echo "  could be asked. The ioreg section is the only evidence available."
        echo
    else
        echo "## kmutil showloaded -a x86_64 -v  (filtered to the two artefacts)"
        echo "  query_status : OK"
        printf '%s\n' "$QUERY_OUT" |
            grep -E 'AMDMapperProbe|RTL812x' ||
            echo "  <neither kext is reported by kmutil>"
        echo
        echo "## the uuid the kernel reports for each, if present"
        #
        # R3: on a FAILED query there is no line at all. Round 12 printed
        # `<not reported by kmutil>` here, which reads as "not loaded" -- the
        # exact confusion this file exists to prevent. A missing line on an OK
        # query is different: the kernel answered and did not mention the kext,
        # so THAT is what is written, with the word "loaded" attached to a
        # definite negative.
        for name in AMDMapperProbe RTL812xLucy; do
            line=$(query_line_for "$name" || true)
            if [ -n "$line" ]; then
                echo "${name}_loaded_line    : $line"
                echo "${name}_loaded_uuid    : $(query_uuid_for "$line" | sed 's/^$/<no uuid in the line>/')"
                echo "${name}_loaded_version : $(query_version_for "$line" | sed 's/^$/<no version in the line>/')"
                echo "${name}_loaded         : yes"
            else
                echo "${name}_loaded_line    : <the kernel did not report this kext>"
                echo "${name}_loaded         : no (the query succeeded and did not list it)"
            fi
        done
    fi
    echo

    echo "# ---- did the driver actually match a device? ----"
    echo
    echo "## ioreg: a started RTL8125 instance"
    if ioreg -l 2>/dev/null | grep -q 'IOClass.*RTL8125'; then
        ioreg -l 2>/dev/null | grep -m3 -E 'IOClass.*RTL8125|CFBundleIdentifier.*RTL812xLucy' |
            sed 's/^/  /'
        echo "  driver_instance : PRESENT"
    else
        echo "  driver_instance : ABSENT (no RTL8125 instance in the IORegistry)"
    fi
    echo

    echo "## ioreg: the probe's own instance"
    if ioreg -l 2>/dev/null | grep -q 'org_maz1_AMDMapperProbe'; then
        echo "  probe_instance  : PRESENT"
        ioreg -l 2>/dev/null | grep -m1 '"m2-b2-verdict"' | sed 's/^/  /'
    else
        echo "  probe_instance  : ABSENT"
    fi
    echo

    echo "# ---- the driver's observation-log identity ----"
    echo
    echo "## rtl812x-obs-epoch: the driver instance that produced the log"
    if ioreg -l 2>/dev/null | grep -q 'rtl812x-obs-epoch'; then
        ioreg -l 2>/dev/null | grep -m1 'rtl812x-obs-epoch' | sed 's/^/  /'
    else
        echo "  rtl812x-obs-epoch : ABSENT (the loaded driver does not publish one)"
        echo "  NOTE: this means the loaded RTL812xLucy is NOT the patched build,"
        echo "        or the patch's log did not initialise."
    fi
    echo

    echo "# ---- HOW TO READ THIS FILE ----"
    echo "#"
    echo "#   identity_source : kmutil"
    echo "#     The kernel answered about BOTH artefacts. The UUIDs above are"
    echo "#     the load identity and may be compared with artefact-identity.txt."
    echo "#"
    echo "#   identity_source : kmutil-partial"
    echo "#     The kernel answered but not about both. The one it did answer"
    echo "#     about is identified; the other is NOT 'not loaded' -- it is"
    echo "#     unaccounted for, and this record does not close it."
    echo "#"
    echo "#   identity_source : ioreg-only"
    echo "#     The kmutil query FAILED. ioreg shows the instances are running,"
    echo "#     which proves SOMETHING is loaded -- not WHICH BINARY it is. The"
    echo "#     load identity is OPEN; re-run this script with root."
    echo "#"
    echo "#   identity_source : UNKNOWN"
    echo "#     Neither source answered. Nothing about the load identity is"
    echo "#     known from this record."
    echo "#"
    echo "#   Anything ABSENT in the ioreg section means the load identity is"
    echo "#   NOT closed, and no amount of matching UUIDs on disk can substitute"
    echo "#   for it."
} > "$OUT"

echo "wrote ${OUT#$ROOT/}"
echo "identity_source: $IDENTITY_SOURCE  (query_status: $QUERY_STATUS)"
cat "$OUT"
