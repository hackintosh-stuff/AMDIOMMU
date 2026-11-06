#!/bin/sh
# deploy-r10.sh -- install the round-10 driver + probe and rebuild the AuxKC.
#
# RUN ON THE MAC. Needs sudo (the account has NOPASSWD).
#
# WHY EVERY CHECK HERE EXISTS
# ---------------------------
# Round 9 lost two whole runs to silent deployment failures:
#   1. deploy-m2-2b2.sh said "Lucy stays untouched", so the patched driver was
#      never installed. The probe reported SKIP-format-unknown and the verdict
#      degraded, while the deploy output said nothing at all.
#   2. Once the driver WAS installed, the copied Info.plist was an unexpanded
#      Xcode template, so kmutil silently dropped the bundle from the aux
#      collection.
# Both had the same shape: every layer reported success, the evidence had
# nothing. So this script checks, after installing, that the thing it installed
# is the thing that is loaded -- by UUID, by wire version, and by bundle id.
set -eu

DRV_KEXT=${1:-$HOME/r10-build/RTL812xLucy.kext}
PRB_KEXT=${2:-$HOME/r10-probe-build/AMDMapperProbe.kext}
WANT_WIRE=${3:-2}

[ -d "$DRV_KEXT" ] || { echo "FAIL: no driver bundle at $DRV_KEXT"; exit 1; }
[ -d "$PRB_KEXT" ] || { echo "FAIL: no probe bundle at $PRB_KEXT"; exit 1; }

echo "== before =="
BEFORE_DRV=$(xcrun dwarfdump --uuid \
    /Library/Extensions/RTL812xLucy.kext/Contents/MacOS/RTL812xLucy 2>/dev/null \
    | awk '{print $2}' | head -1) || BEFORE_DRV=none
BEFORE_PRB=$(xcrun dwarfdump --uuid \
    /Library/Extensions/AMDMapperProbe.kext/Contents/MacOS/AMDMapperProbe 2>/dev/null \
    | awk '{print $2}' | head -1) || BEFORE_PRB=none
echo "driver uuid: $BEFORE_DRV"
echo "probe  uuid: $BEFORE_PRB"

# ---- the driver bundle must carry the v2 wire format --------------------
#
# A v1 driver builds and installs perfectly well; it just publishes records no
# round-10 reader accepts. That failure would only appear at analysis time, so
# it is refused here.
if ! strings "$DRV_KEXT/Contents/MacOS/RTL812xLucy" | grep -q 'rtl812x-obs/2'; then
    echo "FAIL: the driver bundle does not carry the v2 wire format"
    echo "      (found: $(strings "$DRV_KEXT/Contents/MacOS/RTL812xLucy" \
            | grep -o 'rtl812x-obs/[0-9]*' | head -1))"
    exit 1
fi
if ! strings "$DRV_KEXT/Contents/MacOS/RTL812xLucy" | grep -q 'rtl812x-obs-snapshot'; then
    echo "FAIL: the driver bundle does not publish the single-property snapshot"
    exit 1
fi
echo "driver bundle carries wire v$WANT_WIRE OK"

# ---- and it must have the observation symbols ---------------------------
for sym in obsWrite obsPublish obsInit obsFree obsParseBiz; do
    nm "$DRV_KEXT/Contents/MacOS/RTL812xLucy" 2>/dev/null | grep -q "$sym" || {
        echo "FAIL: $sym missing from the driver binary"; exit 1; }
done
echo "observation symbols present OK"

# ---- the probe must understand v2 --------------------------------------
if ! strings "$PRB_KEXT/Contents/MacOS/AMDMapperProbe" | grep -q 'rtl812x-obs/2'; then
    echo "FAIL: the probe bundle does not reference wire v2"
    exit 1
fi
echo "probe understands wire v2 OK"

# ---- the probe must not reference a symbol it does not define ----------
#
# ROUND 10 ADDED THIS CHECK BECAUSE IT CAUGHT A REAL DEFECT. A source splice
# removed the DEFINITION of m2b2ScanTxDone() while leaving the declaration and
# the call site. The probe compiled and linked cleanly (the reference stayed
# external), so the failure only appeared at `kmutil create` time:
#
#   Failed to bind '__ZN26org_maz1_AMDMapperProbe14m2b2ScanTxDoneEv'
#   ... could not find a kext which exports this symbol
#
# and the aux collection was left UNCHANGED, i.e. the old probe would have
# loaded. That is precisely the "every layer reports success, the evidence has
# nothing" pattern. Checking it here turns a 20-minute reboot-and-wonder into
# an immediate, named failure.
UNDEF=$(nm -u "$PRB_KEXT/Contents/MacOS/AMDMapperProbe" 2>/dev/null \
        | awk '{print $NF}' | grep -E '^__ZN26org_example' || true)
if [ -n "$UNDEF" ]; then
    echo "FAIL: the probe references its own symbols but does not define them:"
    echo "$UNDEF"
    exit 1
fi
echo "probe has no undefined symbols of its own class OK"

# ---- bundle identifiers must be expanded, not template text -------------
for k in "$DRV_KEXT" "$PRB_KEXT"; do
    bid=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' \
          "$k/Contents/Info.plist")
    case "$bid" in
        *'${'*|'') echo "FAIL: $k has an unexpanded bundle id: '$bid'"; exit 1 ;;
    esac
    /usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' \
        "$k/Contents/Info.plist" >/dev/null 2>&1 || {
        echo "FAIL: $k has no CFBundleVersion (kmutil will drop it)"; exit 1; }
    echo "bundle id OK: $bid"
done

echo "== install =="
sudo rm -rf /Library/Extensions/RTL812xLucy.kext
sudo rm -rf /Library/Extensions/AMDMapperProbe.kext
sudo cp -R "$DRV_KEXT" /Library/Extensions/
sudo cp -R "$PRB_KEXT" /Library/Extensions/
sudo chown -R root:wheel /Library/Extensions/RTL812xLucy.kext
sudo chown -R root:wheel /Library/Extensions/AMDMapperProbe.kext
sudo chmod -R go-w /Library/Extensions/RTL812xLucy.kext
sudo chmod -R go-w /Library/Extensions/AMDMapperProbe.kext

echo "== rebuild the auxiliary kernel collection =="
# THE EXACT INVOCATION MATTERS. `kmutil install --update-all` and
# `kmutil create --new aux -A <path> --include-volume-kexts` both FAIL on this
# machine: the installed KDK is 25G330 while the running build is 25G332, and
# the explicit forms refuse with "Missing Developer Kit". Worse, some forms
# also fail dependency resolution and silently leave the OLD collection in
# place -- and the only symptom is a capture with none of the new fields.
#
# The form that works, and that every earlier deploy script in this project
# uses, names the three collection paths AND the extensions directory, with
# --allow-missing-kdk and -z (no authorization check).
AUXKC=/Library/KernelCollections/AuxiliaryKernelExtensions.kc
BOOTKC=/System/Library/KernelCollections/BootKernelExtensions.kc
SYSKC=/System/Library/KernelCollections/SystemKernelExtensions.kc
[ -f "$AUXKC.before-r10" ] || sudo cp -p "$AUXKC" "$AUXKC.before-r10"

BEFORE_MT=$(stat -f %m "$AUXKC")
sudo kmutil create -n aux -R / \
    -B "$BOOTKC" -S "$SYSKC" -A "$AUXKC" \
    -r /Library/Extensions --allow-missing-kdk -z -v 2>&1 | tail -6
AFTER_MT=$(stat -f %m "$AUXKC")
echo "auxkc mtime before=$BEFORE_MT after=$AFTER_MT"
[ "$AFTER_MT" != "$BEFORE_MT" ] || {
    echo "FAIL: the auxiliary collection was NOT rebuilt; the old kexts would load"
    exit 1
}

echo "== the collection must actually contain both bundles =="
LIST=$(sudo kmutil inspect -A "$AUXKC" 2>/dev/null || true)
for bid in com.insanelymac.RTL812xLucy org.maz1.AMDMapperProbe; do
    echo "$LIST" | grep -q "$bid" || {
        echo "FAIL: $bid is NOT in the auxiliary collection"
        echo "--- collection ---"
        echo "$LIST" | head -40
        exit 1; }
    echo "in collection OK: $bid"
done

echo "== after =="
AFTER_DRV=$(xcrun dwarfdump --uuid \
    /Library/Extensions/RTL812xLucy.kext/Contents/MacOS/RTL812xLucy 2>/dev/null \
    | awk '{print $2}' | head -1)
AFTER_PRB=$(xcrun dwarfdump --uuid \
    /Library/Extensions/AMDMapperProbe.kext/Contents/MacOS/AMDMapperProbe 2>/dev/null \
    | awk '{print $2}' | head -1)
echo "driver uuid: $AFTER_DRV  (was $BEFORE_DRV)"
echo "probe  uuid: $AFTER_PRB  (was $BEFORE_PRB)"

[ "$AFTER_DRV" != "$BEFORE_DRV" ] || {
    echo "WARN: the driver uuid did not change; if this is the first round-10"
    echo "      install that is expected only when reinstalling the same build."
}
[ "$AFTER_PRB" != "$BEFORE_PRB" ] || {
    echo "WARN: the probe uuid did not change (same build reinstalled)."
}

# ---- declare this round's batch size on the probe's own node ----------
#
# WHY THE VALUE LIVES IN THE PERSONALITY
# --------------------------------------
# controlledBatchComplete must be able to say "the 4 requests I declared all
# completed". The declaration has to exist before the evidence is read, and it
# must not be inferred from the records. The probe reads it from its own
# IORegistry node at start-up, so the value is written into the bundle's
# IOKitPersonalities and therefore takes effect on the next boot.
#
# WHY IT IS WRITTEN AFTER THE INSTALL, TO THE INSTALLED BUNDLE
# ------------------------------------------------------------
# The first version wrote it to the SOURCE bundle before `cp -R`. That looked
# right and was wrong: `kmutil create` reads /Library/Extensions, and the copy
# is what ends up there, so the key has to be on the INSTALLED plist. Writing
# the source bundle only would have left the installed one without the key and
# the probe would silently report expected-batch = 0. It did exactly that.
BATCH=${4:-4}
PERSONALITY=/usr/libexec/PlistBuddy
PLIST="/Library/Extensions/AMDMapperProbe.kext/Contents/Info.plist"
KEY=":IOKitPersonalities:AMDMapperProbe:m2-b2-declared-batch"
sudo $PERSONALITY -c "Set $KEY $BATCH" "$PLIST" 2>/dev/null || \
    sudo $PERSONALITY -c "Add $KEY integer $BATCH" "$PLIST"
GOT=$($PERSONALITY -c "Print $KEY" "$PLIST")
[ "$GOT" = "$BATCH" ] || {
    echo "FAIL: declared batch did not stick (got '$GOT', want '$BATCH')"
    exit 1
}
echo "declared batch: $BATCH (read back from the INSTALLED plist OK)"

echo "DEPLOY OK"
echo "A reboot is required before the new driver and probe are loaded."
