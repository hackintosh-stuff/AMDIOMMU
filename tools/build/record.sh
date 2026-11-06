#!/bin/sh
# build-record.sh -- one clean build of BOTH artefacts, with the record that
# ties each to the source that produced it.
#
# WHY THIS EXISTS
# ---------------
# "I built it and it worked" is not a provenance record. The next run needs to
# be able to answer: which sources produced this kext, with which compiler, at
# which point in a workspace with no version control?
#
# WHAT ROUND 11 GOT WRONG
# -----------------------
#   B1  It recorded only the PROBE. The experiment has two artefacts -- the
#       probe and the patched RTL812xLucy driver -- and the driver is the one
#       that produces the observation log. A record that covers half the
#       system cannot say what produced the records.
#
#   B2  It wrote into a FIXED directory and `rm -rf`'d it first, so a second
#       build silently destroyed the record of the first. The round-11 report
#       then cited a record whose directory had been reused.
#
#   B3  The artefact copy used `|| true`, so a failed copy was swallowed and
#       the record claimed to contain an artefact it did not.
#
#   B4  The record stayed on the Mac. A record that is not in the deliverable
#       is not available to whoever reads the deliverable.
#
# WHAT IT RECORDS NOW, PER ARTEFACT
# ---------------------------------
#   * the exact source list with per-file sha256 and sizes, including the
#     driver patch and its headers;
#   * the driver baseline identity (upstream version + the patch's own sha);
#   * the toolchain and the full compile/link log;
#   * the BUILT binary's uuid and sha256;
#   * the INSTALLED binary's uuid and sha256, if a deployment is present, and
#     an explicit statement that "installed" is not "loaded";
#   * the boot identity and the run id, when the caller supplies them.
#
# THE DISTINCTION THE ROUND-11 REPORT GOT WRONG
# ---------------------------------------------
# A file's UUID on disk is not a load identity. The round-11 report called the
# installed file's UUID "the loaded UUID"; it is not. What is loaded is decided
# by the auxiliary kernel collection at boot. This script therefore records
# three separate facts and never merges them:
#
#     built     the binary this build produced
#     installed the binary present in /Library/Extensions now
#     loaded    what the running kernel reports (only a rebooted run can say)
#
# The `loaded` section is written by tools/verify/record-loaded-frozen.sh AFTER a reboot,
# into the same record directory, so the three sit side by side and a reader can
# see which of them exist.
#
# WHAT THIS SCRIPT DOES NOT DO
# ----------------------------
# It does not deploy, does not load, does not touch /Library/Extensions, and
# does not reboot. Deployment is a separate authorised step.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"

# ---- one directory per build, never reused ------------------------------
#
# The default name carries a UTC timestamp to the second. An explicit argument
# is honoured but REFUSED if it already exists: overwriting a record is how a
# report ends up citing a build that is not the one it describes.
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT=${1:-$ROOT/build-records/$STAMP}
if [ -e "$OUT" ]; then
    echo "FAIL: the record directory already exists: $OUT" >&2
    echo "      A build record is never overwritten: pick a new path." >&2
    exit 1
fi
mkdir -p "$OUT"

echo "== 0. record identity =="
{
    echo "record_dir      : ${OUT#$ROOT/}"
    echo "record_utc      : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "workspace       : ${ROOT##*/}"
    echo "run_id          : ${RUN_ID:-<not supplied>}"
    echo "boot_identity   : ${BOOT_ID:-<not supplied>}"
} | tee "$OUT/record-identity.txt"

# ---- 1. source inventory ------------------------------------------------
echo
echo "== 1. source inventory =="
# ROUND 13: THE HAND-WRITTEN LIST IS NO LONGER THE RECORD.
#
# Round 12 listed the eight modules plus a set of headers and called that the
# source manifest. It was a CLAIM about the build, not a record of it, and it
# omitted real inputs: tools/build/lucy-kmod-info.cpp (a driver translation unit),
# the driver's linux/ headers, the SDK headers, and the compiler/linker command
# lines. It also hashed tools/lucy-obs/*.hpp while the build compiles the
# COPIES the patch installs into the driver directory.
#
# So the authoritative list now comes from the COMPILER: tools/verify/deps.sh runs
# `clang -M` with the same flags the build uses and writes every file the
# preprocessor opened, classified and hashed. The explicit list is kept below
# as a NAMED SUBSET -- the files a reader is most likely to want to check by
# hand -- and the record says which is which.
MODULES="kext/AMDMapperProbe.cpp \
         kext/AMDMapperProbeNic.cpp \
         kext/AMDMapperProbeB1B2Debug.cpp \
         kext/AMDMapperProbeMmioDebug.cpp \
         kext/AMDMapperProbeTableDebug.cpp \
         kext/AMDMapperProbeDmaDebug.cpp \
         kext/AMDMapperProbeObsDebug.cpp \
         kext/AMDMapperProbePgtDebug.cpp \
         kext/AMDMapperProbeInternal.hpp"
HEADERS="kext/AMDMapperProbe.hpp kext/amd_iommu_dma_observe.hpp \
         kext/amd_iommu_pte_core.hpp kext/amd_iommu_bizwalk_core.hpp \
         kext/AMDMapperProbe-Info.plist kext/Info.plist"
# The OTHER artefact: the driver patch and the headers it installs.
DRIVER_PATCH="tools/build/patch-lucy-obs.py"
DRIVER_HEADERS="tools/lucy-obs/RTL812xObsLog.hpp \
                tools/lucy-obs/RTL812xObsWrite.hpp"

{
    echo "# PROBE -- the NAMED SUBSET of the inputs."
    echo "#"
    echo "# THIS IS NOT THE COMPLETE LIST. The authoritative, compiler-derived"
    echo "# list is probe-inputs.sha256 (see probe-deps.raw.txt for the raw"
    echo "# clang -M output). This file exists so a reader can check the files"
    echo "# that matter most by hand without parsing 300 SDK paths."
    echo "# generated $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo
    for f in $MODULES; do
        printf '%s  %8d  %s\n' "$(shasum -a 256 "$f" | awk '{print $1}')" \
               "$(stat -f %z "$f")" "$f"
    done
    echo
    echo "# headers the modules include"
    for f in $HEADERS; do
        [ -f "$f" ] || continue
        printf '%s  %8d  %s\n' "$(shasum -a 256 "$f" | awk '{print $1}')" \
               "$(stat -f %z "$f")" "$f"
    done
} > "$OUT/probe-source-manifest.sha256"
cat "$OUT/probe-source-manifest.sha256"

{
    echo "# RTL812xLucy -- the NAMED SUBSET of the inputs."
    echo "#"
    echo "# This artefact is an UPSTREAM driver plus a patch. The patch is the"
    echo "# identity that matters: the upstream tree is whatever RTL812xLucy-*/"
    echo "# happens to be present, and the patch is what makes it publish the"
    echo "# observation log. Both are recorded."
    echo "#"
    echo "# NOT the complete list: lucy-inputs.sha256 is the compiler-derived"
    echo "# one, and it includes tools/build/lucy-kmod-info.cpp and the driver's"
    echo "# linux/ headers, neither of which round 12 recorded at all."
    echo "# generated $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo
    echo "# the patch and the headers it installs"
    for f in $DRIVER_PATCH $DRIVER_HEADERS; do
        [ -f "$f" ] || continue
        printf '%s  %8d  %s\n' "$(shasum -a 256 "$f" | awk '{print $1}')" \
               "$(stat -f %z "$f")" "$f"
    done
    echo
    echo "# the driver translation unit round 12 omitted entirely"
    if [ -f tools/build/lucy-kmod-info.cpp ]; then
        printf '%s  %8d  %s\n' \
               "$(shasum -a 256 tools/build/lucy-kmod-info.cpp | awk '{print $1}')" \
               "$(stat -f %z tools/build/lucy-kmod-info.cpp)" \
               "tools/build/lucy-kmod-info.cpp"
    fi
    echo
    echo "# the upstream baseline"
    SRC=$(ls -d RTL812xLucy-*/ 2>/dev/null | head -1)
    if [ -n "$SRC" ]; then
        SRC=${SRC%/}
        echo "baseline_dir    : $SRC"
        # Every upstream source file the build compiles, with its hash, so the
        # baseline is identified by CONTENT rather than by a directory name
        # that could be replaced.
        for f in "$SRC"/RTL812xLucy/*.cpp "$SRC"/RTL812xLucy/*.c; do
            [ -f "$f" ] || continue
            printf '%s  %8d  %s\n' \
                   "$(shasum -a 256 "$f" | awk '{print $1}')" \
                   "$(stat -f %z "$f")" "$f"
        done
        for f in "$SRC"/RTL812xLucy/*.pch; do
            [ -f "$f" ] || continue
            printf '%s  %8d  %s\n' \
                   "$(shasum -a 256 "$f" | awk '{print $1}')" \
                   "$(stat -f %z "$f")" "$f"
        done
    else
        echo "baseline_dir    : MISSING (RTL812xLucy-*/ not found)"
    fi
} > "$OUT/lucy-source-manifest.sha256"
cat "$OUT/lucy-source-manifest.sha256"

# ---- 1b. the compiler's own dependency list ----------------------------
#
# ROUND 13. Runs BEFORE the build, so a header-copy mismatch fails the record
# before a four-minute compile. deps.sh exits non-zero when the driver's header
# copies differ from the tool copies -- which means the manifest would describe
# a file the build does not use.
echo
echo "== 1b. compiler-derived input list =="
if ! sh tools/verify/deps.sh "$OUT" > "$OUT/deps.log" 2>&1; then
    echo "FAIL: the compiler-derived input list could not be produced." >&2
    tail -20 "$OUT/deps.log" >&2
    exit 1
fi
tail -6 "$OUT/deps.log"

# ---- 2. toolchain -------------------------------------------------------
echo
echo "== 2. toolchain =="
{
    echo "date_utc        : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "kernel          : $(uname -a)"
    echo "sw_vers         : $(sw_vers -productVersion) ($(sw_vers -buildVersion))"
    echo "sdk_path        : $(xcrun --sdk macosx --show-sdk-path)"
    echo "sdk_version     : $(xcrun --sdk macosx --show-sdk-version)"
    echo "clang           : $(xcrun clang++ --version | head -1)"
    echo "ld              : $(xcrun ld -v 2>&1 | head -1)"
    echo "hw.model        : $(sysctl -n hw.model)"
    echo "hw.tbfrequency  : $(sysctl -n hw.tbfrequency)"
    echo "xcode_select    : $(xcode-select -p 2>/dev/null || echo '<none>')"
} | tee "$OUT/toolchain.txt"

# ---- 3. build the probe -------------------------------------------------
echo
echo "== 3. build the probe (clean, in its own directory) =="
if ! sh tools/build/probe.sh > "$OUT/probe-build.log" 2>&1; then
    echo "BUILD FAILED -- see $OUT/probe-build.log" >&2
    tail -30 "$OUT/probe-build.log" >&2
    exit 1
fi
KEXT=$(cat latest-m1a-build.txt)
BIN="$KEXT/Contents/MacOS/AMDMapperProbe"
# An explicit existence check, not just a later hash.
#
# `set -e` does NOT stop on a failure inside a command substitution used in an
# assignment: `x=$(shasum missing)` leaves x empty and the script continues.
# The verification test found exactly that -- a build whose binary was missing
# still produced a complete-looking record. So each artefact is checked here,
# by name, before anything is recorded about it.
if [ ! -f "$BIN" ]; then
    echo "FAIL: the probe build produced no binary at $BIN" >&2
    tail -20 "$OUT/probe-build.log" >&2
    exit 1
fi
echo "  kext  : $KEXT"
echo "  binary: $BIN"

# ---- 4. build the driver ------------------------------------------------
echo
echo "== 4. patch and build RTL812xLucy =="
if ! sh tools/build/lucy.sh > "$OUT/lucy-build.log" 2>&1; then
    echo "BUILD FAILED -- see $OUT/lucy-build.log" >&2
    tail -30 "$OUT/lucy-build.log" >&2
    exit 1
fi
LKEXT=$(cat latest-lucy-build.txt)
LBIN="$LKEXT/Contents/MacOS/RTL812xLucy"
if [ ! -f "$LBIN" ]; then
    echo "FAIL: the driver build produced no binary at $LBIN" >&2
    echo "      A record that describes an artefact it does not have is" >&2
    echo "      worse than no record: round 11's copy step swallowed this" >&2
    echo "      with '|| true' and the README still claimed the bundle." >&2
    tail -20 "$OUT/lucy-build.log" >&2
    exit 1
fi
echo "  kext  : $LKEXT"
echo "  binary: $LBIN"

# ---- 5. built-artefact identity -----------------------------------------
echo
echo "== 5. built artefact identity =="
{
    echo "# THE BUILT BINARY -- what this build produced."
    echo "# This is NOT a load identity: nothing here says the kernel loaded it."
    echo
    echo "probe_kext_path   : $KEXT"
    echo "probe_sha256      : $(shasum -a 256 "$BIN" | awk '{print $1}')"
    echo "probe_uuid        : $(xcrun dwarfdump --uuid "$BIN" | awk '{print $2}' | head -1)"
    echo "probe_version     : $(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$KEXT/Contents/Info.plist" 2>/dev/null || echo unknown)"
    echo "probe_bundle_id   : $(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$KEXT/Contents/Info.plist" 2>/dev/null || echo unknown)"
    echo "probe_filetype    : $(otool -h "$BIN" | awk 'NR>1{print $5}' | tail -1)"
    echo "probe_undef_syms  : $(nm -u "$BIN" | wc -l | tr -d ' ')"
    echo
    echo "# module entry points: one per translation unit, all must be T (defined)"
    for name in initHardware findTarget runB1SelfTest runM20ConfigProbe \
                runM22bTableProbe observeDeviceDma m2b2ReadDriverObs \
                runM22b2PageTableProbe m2b2WalkBusinessRanges \
                m2b2BindDriverInstance; do
        if nm "$BIN" | grep -q "T .*org_maz1_AMDMapperProbe.*$name"; then
            echo "  T  $name"
        else
            echo "  MISSING  $name"
        fi
    done
    echo
    echo "# the weak-symbol guard: kmutil refuses a bundle with a weak"
    echo "# ____chkstk_darwin reference, so its absence is recorded here too."
    if nm -m "$BIN" | grep -q 'weak.*____chkstk_darwin'; then
        echo "  chkstk            : WEAK REFERENCE PRESENT -- kmutil will refuse"
    else
        echo "  chkstk            : no weak reference"
    fi
    echo
    echo "lucy_kext_path    : $LKEXT"
    echo "lucy_sha256       : $(shasum -a 256 "$LBIN" | awk '{print $1}')"
    echo "lucy_uuid         : $(xcrun dwarfdump --uuid "$LBIN" | awk '{print $2}' | head -1)"
    echo "lucy_version      : $(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$LKEXT/Contents/Info.plist" 2>/dev/null || echo unknown)"
    echo "lucy_bundle_id    : $(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$LKEXT/Contents/Info.plist" 2>/dev/null || echo unknown)"
    echo "lucy_filetype     : $(otool -h "$LBIN" | awk 'NR>1{print $5}' | tail -1)"
    echo "lucy_wire_format  : $(strings "$LBIN" | grep -m1 'rtl812x-obs/2' || echo '<not found>')"
} > "$OUT/artefact-identity.txt"
cat "$OUT/artefact-identity.txt"

# ---- 6. installed-artefact identity -------------------------------------
#
# Recorded SEPARATELY and labelled as installed, never as loaded. If a
# deployment is present it is a fact worth recording -- but it is a different
# fact from "this is what the kernel is running".
#
# ROUND 13: WHAT THIS SECTION DESCRIBES, AND WHEN.
#
# This runs immediately after the build and BEFORE any deployment. So the file
# it finds in /Library/Extensions is whatever the PREVIOUS deployment installed,
# which is normally the round-13-1 artefact, not the one just built. Round 12
# left a reader to work that out. The file now says so in its first line and
# repeats the built hash next to the installed one, so "these differ" is
# visible rather than inferable.
#
# If a deployment has already happened when this script runs (DEPLOYED=1),
# that is recorded instead, and the comparison is meaningful.
echo
echo "== 6. installed artefact identity (state at BUILD time) =="
BUILT_PROBE_SHA=$(shasum -a 256 "$BIN" | awk '{print $1}')
BUILT_LUCY_SHA=$(shasum -a 256 "$LBIN" | awk '{print $1}')
{
    echo "# THE INSTALLED BINARY -- what was in /Library/Extensions at the"
    echo "# moment this BUILD RECORD was written."
    echo "#"
    echo "# THIS IS NOT A LOAD IDENTITY. A file can be installed and not loaded,"
    echo "# loaded from an older auxiliary collection, or replaced while the"
    echo "# running kernel still holds the previous one. The load identity is"
    echo "# written by tools/verify/record-loaded.sh after a reboot, and only the"
    echo "# running kernel can supply it."
    echo "#"
    echo "# ROUND 13: this section runs BEFORE any deployment, so unless"
    echo "# DEPLOYED=1 was set, the files below are the PREVIOUS deployment and"
    echo "# are EXPECTED to differ from the built hashes. Round 12 presented an"
    echo "# installed-identity.txt without saying which deployment it described."
    echo
    echo "record_phase      : $([ "${DEPLOYED:-0}" = "1" ] && echo after-deployment || echo before-deployment)"
    echo
    echo "built_probe_sha256    : $BUILT_PROBE_SHA"
    echo "built_lucy_sha256     : $BUILT_LUCY_SHA"
    echo
    for pair in "probe:/Library/Extensions/AMDMapperProbe.kext/Contents/MacOS/AMDMapperProbe" \
                "lucy:/Library/Extensions/RTL812xLucy.kext/Contents/MacOS/RTL812xLucy"; do
        name=${pair%%:*}
        path=${pair#*:}
        if [ -f "$path" ]; then
            isha=$(shasum -a 256 "$path" | awk '{print $1}')
            echo "${name}_installed_path   : $path"
            echo "${name}_installed_sha256 : $isha"
            echo "${name}_installed_uuid   : $(xcrun dwarfdump --uuid "$path" 2>/dev/null | awk '{print $2}' | head -1)"
            if [ "$name" = "probe" ]; then bs=$BUILT_PROBE_SHA; else bs=$BUILT_LUCY_SHA; fi
            if [ "$isha" = "$bs" ]; then
                echo "${name}_installed_is_built : YES (the installed file is the one just built)"
            else
                echo "${name}_installed_is_built : NO (the installed file is a DIFFERENT build)"
            fi
        else
            echo "${name}_installed_path   : <not installed>"
        fi
    done
    echo
    echo "# the auxiliary collection, if one has been built"
    AUX=/System/Library/KernelCollections/AuxiliaryKernelExtensions.kc
    if [ -e "$AUX" ]; then
        echo "auxkc_path        : $AUX"
        echo "auxkc_mtime       : $(stat -f '%Sm' -t '%Y-%m-%dT%H:%M:%SZ' "$AUX")"
        echo "auxkc_sha256      : $(shasum -a 256 "$AUX" | awk '{print $1}')"
    else
        echo "auxkc_path        : <absent>"
    fi
} > "$OUT/installed-identity.txt"
cat "$OUT/installed-identity.txt"

# ---- 7. copy the artefacts and the record out together ------------------
#
# NO `|| true`. Round 11 swallowed a failed copy and then wrote a README that
# claimed the directory contained the artefact. A record that lies about its
# own contents is worse than no record.
echo
echo "== 7. copy the artefacts into the record =="
mkdir -p "$OUT/AMDMapperProbe.kext" "$OUT/RTL812xLucy.kext"
cp -R "$KEXT/Contents" "$OUT/AMDMapperProbe.kext/" || {
    echo "FAIL: could not copy the probe bundle into the record" >&2; exit 1; }
cp -R "$LKEXT/Contents" "$OUT/RTL812xLucy.kext/" || {
    echo "FAIL: could not copy the driver bundle into the record" >&2; exit 1; }

# Verify the copy: a copy that silently produced a truncated file would make
# the record's own hashes wrong, and the record is the thing being trusted.
for pair in "probe:$BIN:$OUT/AMDMapperProbe.kext/Contents/MacOS/AMDMapperProbe" \
            "lucy:$LBIN:$OUT/RTL812xLucy.kext/Contents/MacOS/RTL812xLucy"; do
    name=${pair%%:*}; rest=${pair#*:}
    src=${rest%%:*}; dst=${rest#*:}
    a=$(shasum -a 256 "$src" | awk '{print $1}')
    b=$(shasum -a 256 "$dst" | awk '{print $1}')
    if [ "$a" != "$b" ]; then
        echo "FAIL: the $name copy does not match the built binary" >&2
        echo "      built $a" >&2
        echo "      copy  $b" >&2
        exit 1
    fi
    echo "  $name copy verified: $a"
done

# ---- 8. README ----------------------------------------------------------
{
    echo "BUILD RECORD"
    echo "============"
    echo "record_dir    : ${OUT#$ROOT/}"
    echo "built (UTC)   : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo
    echo "FILES"
    echo "  record-identity.txt          which build this is"
    echo "  toolchain.txt                compiler, SDK, kernel, machine"
    echo "  probe-source-manifest.sha256 the NAMED SUBSET of probe inputs"
    echo "  lucy-source-manifest.sha256  the NAMED SUBSET of driver inputs"
    echo "  probe-inputs.sha256          EVERY probe input the COMPILER opened"
    echo "  lucy-inputs.sha256           EVERY driver input the COMPILER opened"
    echo "  probe-deps.raw.txt           the raw clang -M output"
    echo "  lucy-deps.raw.txt            the raw clang -M output"
    echo "  build-commands.txt           the exact compile and link command lines"
    echo "  sdk-identity.txt             the SDK, identified not copied"
    echo "  obs-header-identity.txt      tool header == driver header, per file"
    echo "  probe-build.log              full compiler and linker output"
    echo "  lucy-build.log               full compiler and linker output"
    echo "  artefact-identity.txt        the BUILT binaries' uuid and sha256"
    echo "  installed-identity.txt       what was in /Library/Extensions at BUILD time"
    echo "  AMDMapperProbe.kext/         the built probe bundle, verified"
    echo "  RTL812xLucy.kext/            the built driver bundle, verified"
    echo "  loaded-identity.txt          (written later, after a reboot)"
    echo
    echo "THE INPUT LIST IS THE COMPILER'S, NOT A HAND-WRITTEN ONE"
    echo "  Round 12 recorded a list of files it believed the build used. That"
    echo "  list omitted tools/build/lucy-kmod-info.cpp (a real translation unit of the"
    echo "  driver), the driver's linux/ headers, and every SDK header. The"
    echo "  authoritative lists here come from 'clang -M' run with the build's own"
    echo "  flags, so they cannot go stale without the build going stale too."
    echo
    echo "THREE DIFFERENT FACTS, DELIBERATELY NOT MERGED"
    echo "  built      artefact-identity.txt"
    echo "  installed  installed-identity.txt  (state at BUILD time)"
    echo "  loaded     loaded-identity.txt     (absent until a rebooted run records it)"
    echo
    echo "  A file's UUID on disk is NOT a load identity. The round-11 report"
    echo "  called the installed file's UUID \"the loaded UUID\"; it is not."
    echo "  What is loaded is decided by the auxiliary kernel collection at"
    echo "  boot, and only the running kernel can report it."
    echo
    echo "TO CHECK THAT A BINARY CAME FROM THIS SOURCE"
    echo "  1. shasum -a 256 <binary>  == artefact-identity.txt probe_sha256"
    echo "  2. every line of probe-inputs.sha256 / lucy-inputs.sha256 still"
    echo "     matches on disk (this includes the SDK headers, so a different"
    echo "     SDK is detectable)"
    echo "  3. rebuild and compare -- BUT SEE THE WARNING BELOW."
    echo
    echo "  ROUND 13 CORRECTION: THE BUILD IS NOT ALWAYS BYTE-REPRODUCIBLE."
    echo "  Round 12's record said \"the build is deterministic at -O0 with a"
    echo "  fixed SDK, so the uuid and sha256 should match\". That was never"
    echo "  tested, and it is FALSE for the probe: clang generates a fresh"
    echo "  LC_UUID on every link, which changes the whole file and its ad-hoc"
    echo "  signature. Measured on this machine (tools/r13/"
    echo "  verify-reproducibility.py):"
    echo "      probe  sha256 DIFFERS between builds, __text IDENTICAL"
    echo "      driver sha256 IDENTICAL between builds (built without -g)"
    echo "  So: compare __text, not sha256, or compare the UUIDs of ONE build."
    echo "  A sha256 difference between two rebuilds proves nothing."
    echo
    echo "WHAT THIS RECORD DOES NOT SAY"
    echo "  It says nothing about whether the binary was DEPLOYED, or whether a"
    echo "  run used it. Those are separate facts, recorded in the capture's"
    echo "  system.txt (which hashes the INSTALLED kext) and in"
    echo "  loaded-identity.txt. A build record is not a run record; conflating"
    echo "  them is how an old experiment gets reported as a new one."
} > "$OUT/README.txt"

echo
echo "== done =="
echo "record: ${OUT#$ROOT/}"
ls -la "$OUT"
printf '%s\n' "$OUT" > "$ROOT/latest-build-record.txt"
