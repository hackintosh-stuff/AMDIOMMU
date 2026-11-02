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
#   kmutil showloaded -a -v      the auxiliary collection's view: which kexts
#                                the kernel reports as loaded, with their
#                                version and, with -v, their UUID
#   ioreg -l                     the live driver instance: whether the RTL8125
#                                personality actually matched and started
#   sysctl kern.boottime         the boot this observation belongs to, so a
#                                record cannot be silently attributed to a
#                                different boot
#   nvram boot-args              the arguments the kernel was given, which is
#                                what decides the probe's mode
#
# Usage: record-loaded.sh <build-record-dir>
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
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

{
    echo "# THE LOADED IDENTITY -- what the RUNNING KERNEL reports."
    echo "#"
    echo "# This is the only one of the three that answers \"what is loaded\"."
    echo "# It belongs to one boot; the boot time below is part of the record."
    echo
    echo "recorded_utc      : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "boot_time         : $(sysctl -n kern.boottime)"
    echo "kernel            : $(uname -a)"
    echo "sw_vers           : $(sw_vers -productVersion) ($(sw_vers -buildVersion))"
    echo
    echo "boot_args         : $(nvram boot-args 2>/dev/null | sed 's/^boot-args\t//' || echo '<unreadable>')"
    echo

    echo "# ---- what the kernel says is loaded ----"
    echo
    # `kmutil showloaded -a` REQUIRES an architecture argument: `-a x86_64`.
    # Without it the command prints "Missing value for '-a <arch>'" and exits
    # non-zero, so the grep finds nothing and the script reported
    # "<not loaded>" for two kexts that ioreg shows running.
    #
    # That is exactly the failure this file exists to prevent: a check that
    # reports absence because IT failed, not because the thing is absent. The
    # first run of this round hit it, and the ioreg section is what exposed the
    # contradiction. So the command's own status is now recorded, and a failed
    # query is reported as UNKNOWN rather than as "not loaded".
    echo "## kmutil showloaded -a x86_64 -v  (filtered to the two artefacts)"
    if ! sudo -n true 2>/dev/null; then
        echo "  <sudo requires a password; kmutil showloaded needs root>"
        echo "  RUN: sudo kmutil showloaded -a x86_64 -v | grep -E 'AMDMapperProbe|RTL812x'"
        echo "  query_status : UNKNOWN (no root)"
    else
        SL_OUT=$(sudo kmutil showloaded -a x86_64 -v 2>&1)
        SL_RC=$?
        if [ "$SL_RC" -ne 0 ]; then
            echo "  query_status : FAILED (kmutil exited $SL_RC)"
            echo "  kmutil said  : $SL_OUT"
            echo "  A FAILED QUERY IS NOT 'NOT LOADED'. The ioreg section below"
            echo "  is the authoritative answer for this boot."
        else
            echo "  query_status : OK"
            printf '%s\n' "$SL_OUT" |
                grep -E 'AMDMapperProbe|RTL812x' ||
                echo "  <neither kext is reported by kmutil>"
        fi
    fi
    echo

    echo "## the uuid the kernel reports for each, if present"
    #
    # `kmutil showloaded -v` puts the UUID in the TEXT of the line (after the
    # version, before the dependency list), NOT after a "uuid:" label. The
    # first version of this script searched for "uuid:" and therefore printed
    # an EMPTY uuid next to a line that plainly contained one -- a check that
    # reports absence because its pattern was wrong.
    #
    # The UUID is the last bare UUID-shaped token on the line.
    for name in AMDMapperProbe RTL812xLucy; do
        line=$(sudo kmutil showloaded -a x86_64 -v 2>/dev/null |
               grep -m1 "$name" || true)
        if [ -n "$line" ]; then
            echo "${name}_loaded_line : $line"
            uuid=$(printf '%s' "$line" |
                   grep -oE '[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}' |
                   head -1)
            echo "${name}_loaded_uuid : ${uuid:-<no uuid in the line>}"
            # The version is useful for the same reason: it is what the kernel
            # bound, and it must match the built artefact's CFBundleVersion.
            ver=$(printf '%s' "$line" | sed -n 's/.*(\([0-9.]*\)).*/\1/p' | head -1)
            echo "${name}_loaded_version : ${ver:-<no version in the line>}"
        else
            echo "${name}_loaded_line : <not reported by kmutil>"
            echo "${name}_loaded_uuid : <not reported by kmutil>"
            echo "${name}_loaded_version : <not reported by kmutil>"
        fi
    done
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
    if ioreg -l 2>/dev/null | grep -q 'org_example_AMDMapperProbe'; then
        echo "  probe_instance  : PRESENT"
        # The probe publishes its verdict; recording it here ties the load
        # identity to the run that used it.
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
    echo "#   driver_instance PRESENT + probe_instance PRESENT + an obs epoch"
    echo "#   means: the two artefacts that were BUILT are the two that are"
    echo "#   LOADED, and the driver is publishing the log the probe reads."
    echo "#"
    echo "#   Anything ABSENT means the load identity is NOT closed, and no"
    echo "#   amount of matching UUIDs on disk can substitute for it."
    echo "#"
    echo "#   A query_status of FAILED or UNKNOWN is NOT evidence of absence:"
    echo "#   it means the question could not be asked. The ioreg section is"
    echo "#   what answers it on this boot."
} > "$OUT"

echo "wrote ${OUT#$ROOT/}"
cat "$OUT"
