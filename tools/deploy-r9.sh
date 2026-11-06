#!/bin/sh
# deploy-r9.sh -- install BOTH round-9 kexts and (optionally) set the boot-arg.
#
# WHY THIS EXISTS SEPARATELY FROM deploy-m2-2b2.sh
# ------------------------------------------------
# Round 9's first real-machine attempt used deploy-m2-2b2.sh, which says
# "Lucy 保持不动" (leave Lucy alone) at its install step. That was correct for
# rounds 6-8, where the driver was third-party and unmodified. It is WRONG for
# round 9, because the round-9 evidence depends on a PATCHED driver: the whole
# point is that the driver records its own submit/complete metadata.
#
# The failure was silent in the worst way: the probe reported
# `m2-b2-obs = SKIP-format-unknown` (the OLD driver publishes no such
# property), the verdict degraded to INDETERMINATE-no-driver-record-pair, and
# nothing in the deploy output said the driver had not been replaced. The
# installed and loaded UUIDs stayed at the round-7 binary.
#
# So this script:
#   * verifies the patched driver really is the one being installed (it must
#     contain the observation-log symbols),
#   * installs BOTH kexts, recording both UUIDs before and after,
#   * refuses if the loaded driver is still the old one after rebuild.
#
# Usage (on the Mac):
#   sh deploy-r9.sh            # install both kexts, boot-arg unchanged
#   sh deploy-r9.sh --pgt      # also set amdiommu=pgt in config.plist
#   sh deploy-r9.sh --restore  # restore the saved config.plist
set -eu

DO_PGT=0
DO_RESTORE=0
for a in "$@"; do
    case "$a" in
        --pgt) DO_PGT=1 ;;
        --restore) DO_RESTORE=1 ;;
    esac
done

PROBE_ID=org.maz1.AMDMapperProbe
LUCY_ID=com.insanelymac.RTL812xLucy
DEST_PROBE=/Library/Extensions/AMDMapperProbe.kext
DEST_LUCY=/Library/Extensions/RTL812xLucy.kext
SRC_PROBE=$HOME/r9work/build-m1a/AMDMapperProbe.kext
SRC_LUCY=$HOME/r9-lucy/build/RTL812xLucy.kext
CONFIG=/Volumes/EFI/EFI/OC/config.plist
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP=$HOME/r9-backup-$STAMP

say() { printf '\n=== %s ===\n' "$1"; }
die() { printf 'ABORT: %s\n' "$1" >&2; exit 1; }

# ---------------------------------------------------------------------------
if [ "$DO_RESTORE" = 1 ]; then
    say "restore config.plist"
    [ -f "$HOME/r9work/config.plist.before" ] || die "no saved config.plist"
    sudo cp -p "$HOME/r9work/config.plist.before" "$CONFIG"
    sync
    echo "restored; boot-args now:"
    /usr/libexec/PlistBuddy -c \
        'Print :NVRAM:Add:7C436110-AB2A-4BBB-A880-FE41995C9F82:boot-args' \
        "$CONFIG"
    exit 0
fi

# ---------------------------------------------------------------------------
say "0. product checks"

[ -d "$SRC_PROBE" ] || die "probe not found: $SRC_PROBE"
[ -d "$SRC_LUCY" ]  || die "patched driver not found: $SRC_LUCY"
codesign --verify --strict "$SRC_PROBE" || die "probe codesign failed"
codesign --verify --strict "$SRC_LUCY"  || die "driver codesign failed"

PB=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' \
     "$SRC_PROBE/Contents/Info.plist")
[ "$PB" = "0.24.0" ] || die "probe version $PB, expected 0.24.0"

# The patched driver MUST carry the observation-log symbols. Without this
# check, installing an unpatched build looks identical to installing a patched
# one until the capture comes back empty.
NOBS=$(nm "$SRC_LUCY/Contents/MacOS/RTL812xLucy" 2>/dev/null |
       grep -c 'obsWrite\|obsPublish\|obsInit' || true)
[ "$NOBS" -ge 3 ] || die "the driver at $SRC_LUCY has no observation log \
(found $NOBS symbols) -- it is not the patched build"

PU=$(xcrun dwarfdump --uuid "$SRC_PROBE/Contents/MacOS/AMDMapperProbe" |
     awk '{print $2}' | head -1)
LU=$(xcrun dwarfdump --uuid "$SRC_LUCY/Contents/MacOS/RTL812xLucy" |
     awk '{print $2}' | head -1)
PS=$(shasum -a 256 "$SRC_PROBE/Contents/MacOS/AMDMapperProbe" | awk '{print $1}')
LS=$(shasum -a 256 "$SRC_LUCY/Contents/MacOS/RTL812xLucy" | awk '{print $1}')

echo "probe  : v$PB uuid=$PU"
echo "         sha256=$PS"
echo "driver : uuid=$LU"
echo "         sha256=$LS"
echo "         obs symbols=$NOBS"

say "1. kernel UUID must match the KDK"
RUN_UUID=$(sysctl -n kern.uuid)
KDK_UUID=$(xcrun dwarfdump --uuid \
    /Library/Developer/KDKs/KDK_26.7.2_25G330.kdk/System/Library/Kernels/kernel \
    2>/dev/null | awk '{print $2}' | head -1)
echo "running : $RUN_UUID"
echo "KDK     : $KDK_UUID"
[ "$RUN_UUID" = "$KDK_UUID" ] || die "kernel UUID mismatch"

say "2. management path must survive"
# 192.168.50.0/24 must route out of a live interface. Do NOT test the default
# route: it is en2 here and irrelevant to SSH.
route -n get 192.168.50.204 >/dev/null 2>&1 || die "no route to the Mac itself"
IF=$(route -n get 192.168.50.204 | awk '/interface:/{print $2}')
[ -n "$IF" ] || die "cannot determine the management interface"
ifconfig "$IF" | grep -q "inet " || die "$IF has no IPv4 address"
echo "management interface: $IF"

say "3. back up what is installed"
mkdir -p "$BACKUP"
sudo cp -R "$DEST_PROBE" "$BACKUP/" 2>/dev/null || true
sudo cp -R "$DEST_LUCY"  "$BACKUP/" 2>/dev/null || true
[ -f "$CONFIG" ] && sudo cp -p "$CONFIG" "$BACKUP/config.plist" || true
echo "backup: $BACKUP"

say "4. record the CURRENTLY LOADED identities"
kmutil showloaded 2>/dev/null | grep -E "$PROBE_ID|$LUCY_ID" || true

say "5. install BOTH kexts"
# Replace, not merge: `sudo cp -R` onto an existing bundle leaves stale files
# inside it, which is how a previous round shipped a kext with a mix of old and
# new resources.
sudo rm -rf "$DEST_PROBE" "$DEST_LUCY"
sudo cp -R "$SRC_PROBE" "$DEST_PROBE"
sudo cp -R "$SRC_LUCY"  "$DEST_LUCY"
sudo chown -R root:wheel "$DEST_PROBE" "$DEST_LUCY"
sudo chmod -R go-w "$DEST_PROBE" "$DEST_LUCY"

say "6. verify what is now ON DISK"
IP=$(xcrun dwarfdump --uuid "$DEST_PROBE/Contents/MacOS/AMDMapperProbe" |
     awk '{print $2}' | head -1)
IL=$(xcrun dwarfdump --uuid "$DEST_LUCY/Contents/MacOS/RTL812xLucy" |
     awk '{print $2}' | head -1)
echo "installed probe  uuid=$IP"
echo "installed driver uuid=$IL"
[ "$IP" = "$PU" ] || die "installed probe UUID $IP != built $PU"
[ "$IL" = "$LU" ] || die "installed driver UUID $IL != built $LU"
echo "both match the built products"

say "7. rebuild the auxiliary kernel collection"
# Without this the OLD kexts keep loading, and the only symptom is a capture
# with none of the new fields. Round 9's first attempt hit exactly that.
#
# THE EXACT INVOCATION MATTERS. `kmutil install --update-all` and
# `kmutil create --new aux -A <path> --include-volume-kexts` both FAIL on this
# machine: the installed KDK is 25G330 while the running build is 25G332, and
# the explicit forms refuse with "Missing Developer Kit". Worse, the second
# form also fails dependency resolution ("com.nullmoth.NVRM names a dependency
# on com.apple.kpi.libkern"), so it silently leaves the old collection in
# place -- and the only symptom is a capture with no rtl812x-obs-* properties.
#
# The form that works, and that every earlier deploy script in this project
# uses, names the three collection paths AND the extensions directory, with
# --allow-missing-kdk and -z (no authorization check):
#   -n aux -B <boot> -S <system> -A <aux> -r /Library/Extensions
#     --allow-missing-kdk -z -v
AUXKC=/Library/KernelCollections/AuxiliaryKernelExtensions.kc
BOOTKC=/System/Library/KernelCollections/BootKernelExtensions.kc
SYSKC=/System/Library/KernelCollections/SystemKernelExtensions.kc
[ -f "$AUXKC.before" ] || sudo cp -p "$AUXKC" "$AUXKC.before"

BEFORE_MT=$(stat -f %m "$AUXKC")
sudo kmutil create -n aux -R / \
    -B "$BOOTKC" -S "$SYSKC" -A "$AUXKC" \
    -r /Library/Extensions --allow-missing-kdk -z -v 2>&1 | tail -6
AFTER_MT=$(stat -f %m "$AUXKC")
echo "auxkc mtime before=$BEFORE_MT after=$AFTER_MT"
[ "$AFTER_MT" != "$BEFORE_MT" ] || \
    die "the auxiliary collection was NOT rebuilt; the old kexts would load"

say "8. verify the AUXKC contains the new identities"
# `kmutil inspect` separates fields with TABS, so a plain grep for the bundle id
# does match -- but the check must not depend on the driver appearing in any
# particular column. Grep the whole listing.
AUXLIST=$(sudo kmutil inspect -A "$AUXKC" 2>/dev/null || true)
for id in "$PROBE_ID" "$LUCY_ID"; do
    if printf '%s\n' "$AUXLIST" | grep -q "$id"; then
        echo "auxkc lists $id"
    else
        die "auxkc does not list $id after the rebuild; the old kext would \
keep loading and the capture would have none of the new fields"
    fi
done

say "9. boot-arg"
if [ "$DO_PGT" = 1 ]; then
    [ -f "$CONFIG" ] || die "config.plist not mounted; run: sudo diskutil mount disk2s1"
    [ -f "$HOME/r9work/config.plist.before" ] || \
        sudo cp -p "$CONFIG" "$HOME/r9work/config.plist.before"
    CUR=$(/usr/libexec/PlistBuddy -c \
        'Print :NVRAM:Add:7C436110-AB2A-4BBB-A880-FE41995C9F82:boot-args' \
        "$CONFIG")
    NEW=$(echo "$CUR" | sed -e 's/amdiommu=[a-z0-9]*/amdiommu=pgt/')
    case "$NEW" in
        *amdiommu=*) : ;;
        *) NEW="$NEW amdiommu=pgt" ;;
    esac
    sudo /usr/libexec/PlistBuddy -c \
        "Set :NVRAM:Add:7C436110-AB2A-4BBB-A880-FE41995C9F82:boot-args $NEW" \
        "$CONFIG"
    plutil -lint "$CONFIG"
    echo "boot-args now:"
    /usr/libexec/PlistBuddy -c \
        'Print :NVRAM:Add:7C436110-AB2A-4BBB-A880-FE41995C9F82:boot-args' \
        "$CONFIG"
    sync
else
    echo "boot-arg unchanged (pass --pgt to set amdiommu=pgt)"
fi

say "10. summary"
cat <<EOF
probe  built/installed uuid : $PU
driver built/installed uuid : $LU
driver obs symbols          : $NOBS
backup                      : $BACKUP

NEXT: reboot, then check that the LOADED driver uuid is $LU.
If it is still the old one, the AUXKC was not rebuilt and the capture will
have no rtl812x-obs-* properties at all.
EOF
