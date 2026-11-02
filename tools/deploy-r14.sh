#!/bin/sh
# deploy-r14.sh -- install the round-14 driver + probe and rebuild the AuxKC.
#
# RUN ON THE MAC. Needs sudo (the account has NOPASSWD).
#
# WHAT ROUND 14 ADDS TO THE DEPLOY GATE
# -------------------------------------
# Round 13 learned that a "successful" deploy can ship a binary without the
# round's code: the patch template is applied by text substitution, so an
# already-patched tree keeps its old method bodies. The build now refuses that
# (body_is_current), but a deploy can still pair a NEW probe with an OLD driver
# -- for example if the driver build was skipped or the wrong bundle was
# copied. Every symbol and every property name this round depends on is
# therefore checked in BOTH binaries before anything is installed.
#
# Usage: deploy-r14.sh [driver-kext] [probe-kext] [batch] [token-hex]
set -eu

DRV_KEXT=${1:-$HOME/r14-build/RTL812xLucy.kext}
PRB_KEXT=${2:-$HOME/r12work/build-m1a/AMDMapperProbe.kext}
BATCH=${3:-4}
TOKEN=${4:-}

[ -d "$DRV_KEXT" ] || { echo "FAIL: no driver bundle at $DRV_KEXT"; exit 1; }
[ -d "$PRB_KEXT" ] || { echo "FAIL: no probe bundle at $PRB_KEXT"; exit 1; }

if [ -z "$TOKEN" ]; then
    TOKEN=$(python3 -c 'import random; print("0x%08x" % random.randrange(1, 2**32))')
fi
TOKEN=$(printf '%s' "$TOKEN" | sed 's/^0[xX]//' | tr 'A-F' 'a-f')
case "$TOKEN" in
    ''|*[!0-9a-f]*) echo "FAIL: run token is not hexadecimal: $TOKEN"; exit 1 ;;
esac
TOKEN_DISPLAY="0x$TOKEN"

mkdir -p "$HOME/r14load"
printf '%s\n' "$TOKEN_DISPLAY" > "$HOME/r14load/token.txt"
printf '%s\n' "$BATCH" > "$HOME/r14load/batch.txt"

echo "== this run's declaration =="
echo "  run token : $TOKEN_DISPLAY"
echo "  batch     : $BATCH"

echo "== before =="
BEFORE_DRV=$(xcrun dwarfdump --uuid \
    /Library/Extensions/RTL812xLucy.kext/Contents/MacOS/RTL812xLucy 2>/dev/null \
    | awk '{print $2}' | head -1) || BEFORE_DRV=none
BEFORE_PRB=$(xcrun dwarfdump --uuid \
    /Library/Extensions/AMDMapperProbe.kext/Contents/MacOS/AMDMapperProbe 2>/dev/null \
    | awk '{print $2}' | head -1) || BEFORE_PRB=none
echo "driver uuid: $BEFORE_DRV"
echo "probe  uuid: $BEFORE_PRB"

DRV_BIN="$DRV_KEXT/Contents/MacOS/RTL812xLucy"
PRB_BIN="$PRB_KEXT/Contents/MacOS/AMDMapperProbe"

# ---- round 13's requirements (unchanged) --------------------------------
for s in 'rtl812x-obs/2' 'rtl812x-obs-snapshot' 'rtl812x-obs-epoch'; do
    strings "$DRV_BIN" | grep -q "$s" || {
        echo "FAIL: the driver bundle does not carry '$s'"; exit 1; }
done
for sym in obsWrite obsPublish obsInit obsFree obsParseBiz; do
    nm "$DRV_BIN" 2>/dev/null | grep -q "$sym" || {
        echo "FAIL: $sym missing from the driver binary"; exit 1; }
done
echo "round-13 observation log present OK"

# ---- round 14: the RX post tables must be in the DRIVER ------------------
#
# The property name, the format string and the four method symbols. A driver
# built from an unpatched or round-13-patched tree has none of them, and the
# probe would then report SKIP-property-absent with no other symptom.
for s in 'rtl812x-rxpost/1' 'rtl812x-rxpost'; do
    strings "$DRV_BIN" | grep -q "$s" || {
        echo "FAIL: the driver does not publish '$s'"
        echo "      (was it built from a tree patched by an older template?)"
        exit 1; }
done
for sym in rxpostInit rxpostFree rxpostCaptureBaseline rxpostRecordRearm \
           rxpostPublish rxpostBumpGen; do
    nm "$DRV_BIN" 2>/dev/null | grep -q "$sym" || {
        echo "FAIL: $sym missing from the driver binary"; exit 1; }
done
echo "round-14 RX post tables present in the driver OK"

# ---- round 14: the probe must carry the RX set code ----------------------
for name in m2b2RxSetRead m2b2WalkRxSet m2b2PublishRxSet; do
    nm "$PRB_BIN" 2>/dev/null | grep -q "T .*org_example_AMDMapperProbe.*$name" || {
        echo "FAIL: the probe does not define $name"; exit 1; }
done
# The stable tokens the probe publishes for this round. Their presence is
# evidence the set logic is compiled in; their absence means the probe would
# report nothing about the RX set while still deploying cleanly.
for tok in rearm-ring-lapped-past-baseline rearm-publication-truncated \
           rearm-ring-empty-but-records-required range-budget-exceeded \
           ring-rebuilt-during-window; do
    strings "$PRB_BIN" | grep -q "$tok" || {
        echo "FAIL: the probe does not carry the RX set reason token '$tok'"
        exit 1; }
done
echo "round-14 RX set present in the probe OK"

# ---- round 13's remaining requirements ---------------------------------
for name in m2b2WalkBusinessRanges m2b2BindDriverInstance \
            m2b2ReadDeclaredToken m2b2ReadDriverObs; do
    nm "$PRB_BIN" 2>/dev/null | grep -q "T .*org_example_AMDMapperProbe.*$name" || {
        echo "FAIL: the probe does not define $name"; exit 1; }
done
for tok in identity-unknown page-table-evidence-failed \
           token-not-resolved-on-declaration records-dropped-by-writer; do
    strings "$PRB_BIN" | grep -q "$tok" || {
        echo "FAIL: the probe does not carry the round-12 evidence gate"; exit 1; }
done
UNDEF=$(nm -u "$PRB_BIN" 2>/dev/null \
        | awk '{print $NF}' | grep -E '^__ZN26org_example' || true)
if [ -n "$UNDEF" ]; then
    echo "FAIL: the probe references its own symbols but does not define them:"
    echo "$UNDEF"
    exit 1
fi
echo "probe carries the round-11/12 entry points OK"

# ---- bundle identifiers must be expanded -------------------------------
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
AUXKC=/Library/KernelCollections/AuxiliaryKernelExtensions.kc
BOOTKC=/System/Library/KernelCollections/BootKernelExtensions.kc
SYSKC=/System/Library/KernelCollections/SystemKernelExtensions.kc
[ -f "$AUXKC.before-r14" ] || sudo cp -p "$AUXKC" "$AUXKC.before-r14"

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
for bid in com.insanelymac.RTL812xLucy org.example.AMDMapperProbe; do
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

# ---- declare this round's batch AND token in the boot-arg --------------
NEWARG="amdiommu=pgt.batch${BATCH}.t0x${TOKEN}"
CUR=$(nvram boot-args 2>/dev/null | sed 's/^boot-args[[:space:]]*//' || echo '')
CLEAN=$(printf '%s' "$CUR" | tr ' ' '\n' | grep -v '^amdiommu=' | tr '\n' ' ')
NEW=$(printf '%s%s' "$CLEAN" "$NEWARG" | sed 's/^ *//; s/ *$//')
sudo nvram boot-args="$NEW"
GOT=$(nvram boot-args 2>/dev/null | sed 's/^boot-args[[:space:]]*//')
case "$GOT" in
    *"$NEWARG"*) echo "boot-arg declared OK: $NEWARG" ;;
    *) echo "FAIL: the boot-arg did not stick. Got: $GOT"; exit 1 ;;
esac

# The EFI config.plist's NVRAM:Add OVERRIDES nvram on every boot, so the same
# value must be present there or the declaration is silently lost.
#
# THIS IS A HARD FAILURE, NOT A WARNING.
#
# Round 14's runs 3 and 4 both declared a token that the probe never saw: the EFI
# volume had been unmounted (it is unmounted by every reboot), so this script's
# earlier "WARNING: no EFI volume mounted" branch was taken, the plist kept the
# FIRST run's token, OpenCore rewrote nvram from it on the next boot, and the
# probe -- correctly -- refused the batch with `controlled-batch-incomplete`.
#
# The load had already used the NEW token from ~/r14load/token.txt, so the two
# channels disagreed and the run was wasted. A warning that lets the run proceed
# is worse than no check: the evidence looks complete and is not.
EFI=$(mount | awk '/EFI/{print $3; exit}')
if [ -z "$EFI" ]; then
    echo "FAIL: no EFI volume is mounted, so the OpenCore boot-args cannot be"
    echo "      updated. OpenCore's NVRAM:Add OVERRIDES nvram on every boot, so"
    echo "      the next boot would use whatever the config.plist already says"
    echo "      and the probe would refuse the batch."
    echo
    echo "      Mount it and run this script again:"
    echo "          sudo diskutil mount disk2s1"
    echo
    echo "      (The EFI is unmounted by every reboot, so this is expected after"
    echo "       a restart -- it is not a sign that something is broken.)"
    exit 1
fi
if [ ! -f "$EFI/EFI/OC/config.plist" ]; then
    echo "FAIL: no config.plist at $EFI/EFI/OC/config.plist"
    exit 1
fi
python3 tools/r13/set-bootarg.py "$EFI/EFI/OC/config.plist" \
    "amdiommu=pgt.batch${BATCH}.t0x${TOKEN}" || {
    echo "FAIL: could not set boot-args in the EFI config.plist"; exit 1; }

# ---- and the two channels must agree BEFORE the reboot -----------------
#
# nvram was set above; the plist was set just now. Read both back and require
# them to carry the same amdiommu value, because that is the condition the run
# depends on and it is cheap to check here rather than discover after 90 s.
NVRAM_ARG=$(nvram boot-args 2>/dev/null | tr ' ' '\n' | grep '^amdiommu=' || true)
PLIST_ARG=$(plutil -p "$EFI/EFI/OC/config.plist" 2>/dev/null \
            | grep -o 'amdiommu=[^" ]*' | head -1 || true)
echo "nvram   : $NVRAM_ARG"
echo "plist   : $PLIST_ARG"
if [ "$NVRAM_ARG" != "$PLIST_ARG" ]; then
    echo "FAIL: the two boot-arg channels disagree. OpenCore would overwrite"
    echo "      nvram from the plist on the next boot, so the probe would read"
    echo "      a different declaration than the load uses."
    exit 1
fi
echo "both boot-arg channels carry the same declaration OK"

echo
echo "DEPLOY OK"
echo "A reboot is required before the new driver and probe are loaded."
echo "This run's declaration: $NEWARG"
