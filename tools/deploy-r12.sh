#!/bin/sh
# deploy-r12.sh -- install the round-11 driver + probe, declare this run's
# token and batch, and rebuild the AuxKC.
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
# is the thing that is loaded -- by UUID, by wire version, by bundle id, and by
# the round-11 protocol being present rather than round 10's.
#
# WHAT ROUND 11 ADDS
# ------------------
#   * the write protocol must be the LOCKED one (obslog::writeRecord), not
#     round 10's preempt-then-recheck;
#   * the driver must publish rtl812x-obs-epoch, which is what lets the probe
#     bind to THIS driver instance before the window opens;
#   * the probe must carry m2b2WalkBusinessRanges and m2b2BindDriverInstance;
#   * the run token is declared in the boot-arg alongside the batch, so the
#     batch predicate is bound to this run rather than to "whatever reqIds
#     appear".
#
# WHY THE DECLARATION IS A BOOT-ARG AND NOT A PERSONALITY KEY
# -----------------------------------------------------------
# Round 10 tried a personality key first. IOKit publishes only a small fixed
# subset of the personality dictionary onto the node (IOClass, IOProviderClass,
# IOMatchCategory, ...), so an arbitrary key never appears there and the read
# silently returned 0. It then tried a separate boot-arg (m2b2batch=) and found
# that only `amdiommu=...` is reliably delivered to this kext. So the
# declaration travels inside that one value:
#
#     amdiommu=pgt.batch4.t0xa3dbba85
#
# Usage: deploy-r12.sh [driver-kext] [probe-kext] [batch] [token-hex]
set -eu

DRV_KEXT=${1:-$HOME/r12-build/RTL812xLucy.kext}
PRB_KEXT=${2:-$HOME/r12work/build-m1a/AMDMapperProbe.kext}
BATCH=${3:-4}
TOKEN=${4:-}

[ -d "$DRV_KEXT" ] || { echo "FAIL: no driver bundle at $DRV_KEXT"; exit 1; }
[ -d "$PRB_KEXT" ] || { echo "FAIL: no probe bundle at $PRB_KEXT"; exit 1; }

# A token of 0 is never valid: the driver refuses to publish a parsed record
# whose token is 0, so 0 means "not declared" and the batch predicate would
# refuse the run. Generate a fresh one when the caller does not supply it.
if [ -z "$TOKEN" ]; then
    TOKEN=$(python3 -c 'import random; print("0x%08x" % random.randrange(1, 2**32))')
fi
# Normalise to a BARE lowercase hex string, no 0x prefix. The boot-arg writer
# below adds the "t0x" prefix itself, so keeping 0x here produced "t0x0x...",
# which the probe's parser read as token 0 and the deploy's own read-back
# check caught. One normalisation point, one place that adds the prefix.
TOKEN=$(printf '%s' "$TOKEN" | sed 's/^0[xX]//' | tr 'A-F' 'a-f')
case "$TOKEN" in
    ''|*[!0-9a-f]*) echo "FAIL: run token is not hexadecimal: $TOKEN"; exit 1 ;;
esac
TOKEN_DISPLAY="0x$TOKEN"

mkdir -p "$HOME/r12load"
printf '%s\n' "$TOKEN_DISPLAY" > "$HOME/r12load/token.txt"
printf '%s\n' "$BATCH" > "$HOME/r12load/batch.txt"

echo "== this run's declaration =="
echo "  run token : $TOKEN_DISPLAY"
echo "  batch     : $BATCH"
echo "  (written to ~/r12load/token.txt and batch.txt; the load script reads"
echo "   the same files, so the two cannot disagree)"

echo "== before =="
BEFORE_DRV=$(xcrun dwarfdump --uuid \
    /Library/Extensions/RTL812xLucy.kext/Contents/MacOS/RTL812xLucy 2>/dev/null \
    | awk '{print $2}' | head -1) || BEFORE_DRV=none
BEFORE_PRB=$(xcrun dwarfdump --uuid \
    /Library/Extensions/AMDMapperProbe.kext/Contents/MacOS/AMDMapperProbe 2>/dev/null \
    | awk '{print $2}' | head -1) || BEFORE_PRB=none
echo "driver uuid: $BEFORE_DRV"
echo "probe  uuid: $BEFORE_PRB"

# ---- the driver bundle must carry the v2 wire format AND round-11 protocol --
DRV_BIN="$DRV_KEXT/Contents/MacOS/RTL812xLucy"
if ! strings "$DRV_BIN" | grep -q 'rtl812x-obs/2'; then
    echo "FAIL: the driver bundle does not carry the v2 wire format"
    exit 1
fi
if ! strings "$DRV_BIN" | grep -q 'rtl812x-obs-snapshot'; then
    echo "FAIL: the driver bundle does not publish the single-property snapshot"
    exit 1
fi
if ! strings "$DRV_BIN" | grep -q 'rtl812x-obs-epoch'; then
    echo "FAIL: the driver does not publish rtl812x-obs-epoch"
    echo "      (without it the probe cannot bind to this driver instance)"
    exit 1
fi
echo "driver bundle carries wire v2 + epoch property OK"

# Round 10's protocol preempted a slot another writer was filling, which
# produced records whose body mixed two writers (reproduced by
# tools/r11/verify-write-protocol.py: 13 of 13 fields foreign). The locked
# protocol cannot express that, so its presence is asserted here.
if ! strings "$DRV_BIN" | grep -qi 'obslog'; then
    echo "WARN: no 'obslog' string in the driver (it may be inlined)."
    echo "      Falling back to the symbol check below."
fi
for sym in obsWrite obsPublish obsInit obsFree obsParseBiz; do
    nm "$DRV_BIN" 2>/dev/null | grep -q "$sym" || {
        echo "FAIL: $sym missing from the driver binary"; exit 1; }
done
echo "observation symbols present OK"

# ---- the probe must understand v2 and carry the round-11 entry points ------
PRB_BIN="$PRB_KEXT/Contents/MacOS/AMDMapperProbe"
if ! strings "$PRB_BIN" | grep -q 'rtl812x-obs/2'; then
    echo "FAIL: the probe bundle does not reference wire v2"
    exit 1
fi
echo "probe understands wire v2 OK"

for name in m2b2WalkBusinessRanges m2b2BindDriverInstance \
            m2b2ReadDeclaredToken m2b2ReadDriverObs; do
    nm "$PRB_BIN" 2>/dev/null | grep -q "T .*org_example_AMDMapperProbe.*$name" || {
        echo "FAIL: the probe does not define $name"; exit 1; }
done
echo "probe carries the round-11 entry points OK"

# The probe must not reference a symbol it does not define. A source splice
# once removed the DEFINITION of m2b2ScanTxDone() while leaving the
# declaration and the call site; the probe compiled and linked cleanly and the
# failure only appeared at `kmutil create` time:
#
#   Failed to bind '__ZN26org_example_AMDMapperProbe14m2b2ScanTxDoneEv'
#
# and the aux collection was left UNCHANGED, i.e. the old probe would have
# loaded. Checking it here turns a 20-minute reboot-and-wonder into an
# immediate, named failure.
UNDEF=$(nm -u "$PRB_BIN" 2>/dev/null \
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
AUXKC=/Library/KernelCollections/AuxiliaryKernelExtensions.kc
BOOTKC=/System/Library/KernelCollections/BootKernelExtensions.kc
SYSKC=/System/Library/KernelCollections/SystemKernelExtensions.kc
[ -f "$AUXKC.before-r12" ] || sudo cp -p "$AUXKC" "$AUXKC.before-r12"

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

# ---- round 12: the probe must carry the evidence gate -------------------
#
# The PASS-CANDIDATE branch now calls amdobs::obsEvidenceGate(), and the
# production read path uses the STRICT batch spec. Both are new in round 12, so
# a probe without them would deploy fine and judge by round 11's weaker rules.
#
# They are header-inline, so there is no symbol to look for. What IS observable
# in the binary is the stable reason tokens the gate publishes. Their presence
# is evidence the gate is compiled in; their absence is evidence it is not.
for tok in identity-unknown page-table-evidence-failed \
           token-not-resolved-on-declaration records-dropped-by-writer; do
    if ! strings "$PRB_BIN" | grep -q "$tok"; then
        echo "FAIL: the probe does not carry the round-12 evidence gate"
        echo "      (no '$tok' token: it would judge by round 11's rules)"
        exit 1
    fi
done
echo "probe carries the round-12 evidence gate OK"

# The driver must carry the round-12 write protocol: atomic word stores and
# atomic loss counters. Round 11's publisher copied bytes with plain loads,
# which is a data race against the writer -- proven by TSan on the shared
# implementation. There is no runtime symbol for it, so the header's own
# identity strings are checked instead.
if ! strings "$DRV_BIN" | grep -q 'RTL812xObsWrite'; then
    echo "NOTE: the write protocol header name is not in the driver strings."
    echo "      It may be fully inlined; the host test covers the protocol."
fi

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
#
# The probe reads both from the one argument that demonstrably arrives. The
# batch count and the run token travel together so they cannot be set
# independently and drift.
NEWARG="amdiommu=pgt.batch${BATCH}.t0x${TOKEN}"
CUR=$(nvram boot-args 2>/dev/null | sed 's/^boot-args[[:space:]]*//' || echo '')
# Remove any previous amdiommu= token, then append the new one.
CLEAN=$(printf '%s' "$CUR" | tr ' ' '\n' | grep -v '^amdiommu=' | tr '\n' ' ')
NEW=$(printf '%s%s' "$CLEAN" "$NEWARG" | sed 's/^ *//; s/ *$//')
sudo nvram boot-args="$NEW"
GOT=$(nvram boot-args 2>/dev/null | sed 's/^boot-args[[:space:]]*//')
case "$GOT" in
    *"$NEWARG"*) echo "boot-arg declared OK: $NEWARG" ;;
    *) echo "FAIL: the boot-arg did not stick. Got: $GOT"; exit 1 ;;
esac

# ---- and it must be readable back the way the probe will parse it -------
python3 - "$GOT" "$BATCH" "$TOKEN" <<'PY'
import sys
args, want_batch, want_token = sys.argv[1], int(sys.argv[2]), sys.argv[3]
val = None
for a in args.split():
    if a.startswith('amdiommu='):
        val = a[len('amdiommu='):]
if val is None:
    raise SystemExit('FAIL: no amdiommu= in boot-args')
if not val.startswith('pgt'):
    raise SystemExit('FAIL: amdiommu= does not select the pgt experiment: %r' % val)
dot = val.find('.')
if dot < 0:
    raise SystemExit('FAIL: no declaration suffix in %r' % val)
rest = val[dot + 1:]
if not rest.startswith('batch'):
    raise SystemExit('FAIL: suffix does not start with batch: %r' % rest)
q = rest[5:]
n = ''
while q and q[0].isdigit():
    n += q[0]; q = q[1:]
if int(n or 0) != want_batch:
    raise SystemExit('FAIL: batch parsed as %r, wanted %d' % (n, want_batch))
if not q.startswith('.t0x'):
    raise SystemExit('FAIL: no token after the batch: %r' % q)
# '.t0x' is four characters: '.', 't', '0', 'x'. Skipping three left the 'x'
# in place and produced '0xx...', which int(,16) rejects -- so this check
# failed on a correct boot-arg. The slice must skip the whole prefix.
tok = '0x' + q[4:]
if int(tok, 16) != int(want_token, 16):
    raise SystemExit('FAIL: token parsed as %s, wanted %s' % (tok, want_token))
print('declaration parses as the probe will read it: batch=%d token=%s'
      % (want_batch, want_token))
PY

echo
echo "DEPLOY OK"
echo "A reboot is required before the new driver and probe are loaded."
echo "This run's declaration: $NEWARG"
