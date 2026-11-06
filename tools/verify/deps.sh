#!/bin/sh
# deps.sh -- record the COMPILER'S OWN view of which files a build consumed.
#
# WHY THIS EXISTS
# ---------------
# Round 12's `build-record.sh` recorded a HAND-WRITTEN list of source files:
#
#     MODULES="kext/AMDMapperProbe.cpp ... kext/AMDMapperProbeInternal.hpp"
#     HEADERS="kext/AMDMapperProbe.hpp kext/amd_iommu_dma_observe.hpp ..."
#
# That list was a claim about the build, not a record of it. It omitted, among
# other things:
#
#   * tools/build/lucy-kmod-info.cpp -- a real translation unit of the DRIVER build
#     (build-lucy.sh compiles it and links it in), absent from the manifest;
#   * the driver's linux/ headers, which the .c files include;
#   * the SDK and MacKernelSDK headers, which decide what the code MEANS;
#   * the compiler and linker command lines.
#
# A source manifest that is written by hand goes stale silently: the build keeps
# working, the manifest keeps looking complete, and the two stop describing the
# same artefact. The cure is to ask the compiler.
#
# HOW
# ---
# `clang -M` emits a make-style dependency rule listing every file the
# preprocessor actually opened, in order, with continuations. That is the
# compiler's own answer to "what did this translation unit consume", including
# headers reached through `-include` and through nested includes.
#
# This script runs `-M` with the SAME flags each build uses, then:
#
#   * writes the raw dependency output for each translation unit, verbatim;
#   * writes a sorted, de-duplicated list of every file, with sha256 and size;
#   * classifies each file as project / driver-baseline / sdk / other, so a
#     reader can see at a glance how much of the input is under this
#     repository's control;
#   * records the exact compile and link command lines.
#
# It does NOT build. It is meant to be called by build-record.sh next to the
# real build, with the same flags, so the two cannot drift.
#
# Usage: deps.sh <outdir>
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
OUT=${1:?outdir}
mkdir -p "$OUT"

SDK=$(xcrun --sdk macosx --show-sdk-path)
SDKVER=$(xcrun --sdk macosx --show-sdk-version)
HEADERS="$SDK/System/Library/Frameworks/Kernel.framework/Versions/A/Headers"

SRC=$(ls -d RTL812xLucy-*/ 2>/dev/null | head -1)
SRC=${SRC%/}
DRV="$SRC/RTL812xLucy"
# THE DRIVER'S SDK HAS ITS OWN NAME HERE.
#
# tools/build/lucy.sh calls the MacKernelSDK directory `SDK`, and
# tools/build/probe.sh calls the macOS SDK directory `SDK`. Both names are right
# in their own script; in one script they would collide. So the two are named
# SYS_SDK (macOS SDK, used by the probe) and MSDK (MacKernelSDK, used by the
# driver), and tools/verify/build-inputs.py resolves each script's own
# variable definitions before comparing the flag strings. Comparing the raw text
# would fail on the naming difference alone and could hide a real one behind it.
SYS_SDK="$SDK"
MSDK="$SRC/MacKernelSDK"

# ---- the probe's flags, copied from tools/build/probe.sh -------------------
#
# COPIED, not sourced: build-m1a.sh is a build script, not a library, and
# sourcing it would run the build. The duplication is checked by
# tools/verify/build-inputs.py, which reads both files and requires the
# flag strings to be identical -- so a change in one without the other is a
# test failure rather than a silent divergence.
PROBE_CFLAGS="-arch x86_64 -mkernel -fapple-kext -mno-red-zone \
    -isysroot $SDK -mmacosx-version-min=$SDKVER \
    -I $HEADERS -nostdinc++ -std=c++17 \
    -DKERNEL -DKERNEL_PRIVATE -DDRIVER_PRIVATE \
    -fno-builtin -fno-common -fno-exceptions -fno-rtti \
    -fno-stack-protector -Wall -Wextra -Werror -O0 -g"

PROBE_SRCS="kext/AMDMapperProbe.cpp \
      kext/AMDMapperProbeNic.cpp \
      kext/AMDMapperProbeB1B2Debug.cpp \
      kext/AMDMapperProbeMmioDebug.cpp \
      kext/AMDMapperProbeTableDebug.cpp \
      kext/AMDMapperProbeDmaDebug.cpp \
      kext/AMDMapperProbeObsDebug.cpp \
      kext/AMDMapperProbePgtDebug.cpp"

# ---- the driver's flags, copied from tools/build/lucy.sh -----------------
LUCY_CFLAGS="-arch x86_64 -mkernel -fapple-kext -mno-red-zone \
 -nostdinc++ -std=gnu++17 -O0 \
 -DKERNEL -DKERNEL_PRIVATE -DDRIVER_PRIVATE -D__APPLE_KEXT__ \
 -fno-builtin -fno-common -fno-exceptions -fno-rtti \
 -fstack-protector -fno-threadsafe-statics \
 -Wno-unused-parameter -Wno-unused-function \
 -I $MSDK/Headers \
 -I $SRC/KernelSPI \
 -I $DRV \
 -I $DRV/linux \
 -include $DRV/RTL8125LucyPrefix.pch"

LUCY_CFLAGS_C="-arch x86_64 -mkernel -fapple-kext -mno-red-zone -O0 \
 -DKERNEL -DKERNEL_PRIVATE -DDRIVER_PRIVATE -D__APPLE_KEXT__ \
 -fno-builtin -fno-common -fstack-protector \
 -Wno-unused-parameter -Wno-unused-function \
 -I $MSDK/Headers \
 -I $SRC/KernelSPI \
 -I $DRV \
 -I $DRV/linux \
 -include $DRV/RTL8125LucyPrefix.pch"

{
    echo "# THE EXACT COMMAND LINES the build uses."
    echo "# deps.sh passes these to the compiler to obtain its dependency list,"
    echo "# so the list and the build cannot use different flags."
    echo
    echo "sdk_path   : $SDK"
    echo "sdk_version: $SDKVER"
    echo "driver_src : $SRC"
    echo
    echo "# probe compile:"
    echo "xcrun clang++ $PROBE_CFLAGS -c <src> -o <obj>"
    echo
    echo "# probe link:"
    echo "xcrun ld -kext -arch x86_64 -sysroot $SDK -platform_version macos $SDKVER $SDKVER <objs> $SDK/usr/lib/libkmod.a -o <bin>"
    echo
    echo "# driver compile (C++):"
    echo "xcrun clang++ $LUCY_CFLAGS -c <src> -o <obj>"
    echo
    echo "# driver compile (C):"
    echo "xcrun clang -x c $LUCY_CFLAGS_C -c <src> -o <obj>"
    echo
    echo "# driver link:"
    echo "xcrun ld -kext -arch x86_64 <objs> $MSDK/Library/universal/libkmodc++.a $MSDK/Library/x86_64/libkmod.a -o <bin>"
} > "$OUT/build-commands.txt"

# ---- the probe's dependency list ---------------------------------------
#
# `-M` writes to stdout by default; `-MM` would drop SYSTEM headers, which are
# exactly the ones round 12 was missing. So `-M`, not `-MM`.
: > "$OUT/probe-deps.raw.txt"
: > "$OUT/probe-inputs.list"
for f in $PROBE_SRCS; do
    echo "### $f" >> "$OUT/probe-deps.raw.txt"
    # shellcheck disable=SC2086
    xcrun clang++ $PROBE_CFLAGS -M "$f" >> "$OUT/probe-deps.raw.txt" 2>&1 || {
        echo "FAIL: the compiler refused to list dependencies for $f" >&2
        exit 1; }
done

# Parse the make-style rules: everything after the colon, continuations joined.
python3 - "$OUT/probe-deps.raw.txt" "$OUT/probe-inputs.list" <<'PY'
import sys

raw, dest = sys.argv[1], sys.argv[2]
text = open(raw, encoding='utf-8', errors='replace').read()
# Join continuations, then collect every token after a rule's colon.
joined = text.replace('\\\n', ' ')
files = []
for line in joined.splitlines():
    if line.startswith('###') or ':' not in line:
        continue
    rhs = line.split(':', 1)[1]
    for tok in rhs.split():
        if tok and tok not in files:
            files.append(tok)
open(dest, 'w', encoding='utf-8').write('\n'.join(files) + '\n')
print('%d distinct files' % len(files))
PY

# ---- the driver's dependency list --------------------------------------
: > "$OUT/lucy-deps.raw.txt"
if [ -d "$DRV" ]; then
    for f in "$DRV"/*.cpp; do
        [ -f "$f" ] || continue
        echo "### $f" >> "$OUT/lucy-deps.raw.txt"
        # shellcheck disable=SC2086
        xcrun clang++ $LUCY_CFLAGS -M "$f" >> "$OUT/lucy-deps.raw.txt" 2>&1 || {
            echo "FAIL: the compiler refused to list dependencies for $f" >&2
            exit 1; }
    done
    for f in "$DRV"/*.c; do
        [ -f "$f" ] || continue
        echo "### $f" >> "$OUT/lucy-deps.raw.txt"
        # shellcheck disable=SC2086
        xcrun clang -x c $LUCY_CFLAGS_C -M "$f" >> "$OUT/lucy-deps.raw.txt" 2>&1 || {
            echo "FAIL: the compiler refused to list dependencies for $f" >&2
            exit 1; }
    done
    # THE TRANSLATION UNIT ROUND 12 NEVER LISTED.
    echo "### tools/build/lucy-kmod-info.cpp" >> "$OUT/lucy-deps.raw.txt"
    # shellcheck disable=SC2086
    xcrun clang++ $LUCY_CFLAGS -M tools/build/lucy-kmod-info.cpp >> "$OUT/lucy-deps.raw.txt" 2>&1 || {
        echo "FAIL: the compiler refused to list dependencies for lucy-kmod-info.cpp" >&2
        exit 1; }
else
    echo "baseline_dir : MISSING (RTL812xLucy-*/ not found)" > "$OUT/lucy-deps.raw.txt"
fi

python3 - "$OUT/lucy-deps.raw.txt" "$OUT/lucy-inputs.list" <<'PY'
import os
import sys

raw, dest = sys.argv[1], sys.argv[2]
text = open(raw, encoding='utf-8', errors='replace').read()
joined = text.replace('\\\n', ' ')
files = []
for line in joined.splitlines():
    if line.startswith('###') or ':' not in line:
        continue
    rhs = line.split(':', 1)[1]
    for tok in rhs.split():
        # THE FILTER IS LOAD-BEARING.
        #
        # `clang -x c ... -fapple-kext` prints
        #
        #     warning: argument unused during compilation: '-fapple-kext'
        #     ... which is valid for C++ and Objective-C++ only
        #
        # and the first version of this parser merged that stderr into the
        # dependency text and then treated its WORDS as input files -- the
        # record listed 'ignoring', 'which', 'is', 'valid' as missing inputs.
        # A dependency token is a path: it contains a separator or ends in a
        # source/header suffix.
        if not tok:
            continue
        if '/' not in tok and not tok.endswith(
                ('.h', '.hpp', '.c', '.cc', '.cpp', '.pch', '.inc')):
            continue
        if tok not in files:
            files.append(tok)
open(dest, 'w', encoding='utf-8').write('\n'.join(files) + '\n')
print('%d distinct files' % len(files))
PY

# ---- hash every input, with a classification ---------------------------
#
# The classification matters: a reader needs to know how much of the input is
# under this repository's control. A header that comes from the SDK cannot be
# reproduced from this workspace, so it is recorded by identity (path, hash)
# and its SDK is recorded by version -- not copied.
python3 - "$OUT" "$ROOT" "$SRC" <<'PY'
import hashlib
import os
import sys

out, root, src = sys.argv[1], sys.argv[2], sys.argv[3]


def sha(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for c in iter(lambda: f.read(1 << 20), b''):
            h.update(c)
    return h.hexdigest()


def classify(p):
    rp = os.path.abspath(p)
    if rp.startswith(os.path.join(root, 'kext')):
        return 'project-kext'
    if rp.startswith(os.path.join(root, 'tools')):
        return 'project-tools'
    if src and rp.startswith(os.path.join(root, src)):
        return 'driver-baseline'
    if '/MacOSX.sdk/' in rp or '/MacOSX.platform/' in rp or \
            '/Kernel.framework/' in rp:
        return 'sdk'
    if '/usr/lib/clang/' in rp or '/usr/include/' in rp:
        return 'compiler'
    return 'other'


for stem in ('probe', 'lucy'):
    lst = os.path.join(out, stem + '-inputs.list')
    if not os.path.exists(lst):
        continue
    files = [l.strip() for l in open(lst) if l.strip()]
    dest = os.path.join(out, stem + '-inputs.sha256')
    counts = {}
    with open(dest, 'w', encoding='utf-8') as f:
        f.write('# %s -- EVERY file the compiler opened, as the compiler\n'
                '# reported it (clang -M). Not a hand-written list.\n'
                % stem.upper())
        f.write('# columns: sha256  size  class  path\n')
        for p in files:
            if not os.path.exists(p):
                f.write('%s  %8s  %-16s  %s\n' % ('MISSING'.ljust(64), '-',
                                                  'missing', p))
                counts['missing'] = counts.get('missing', 0) + 1
                continue
            c = classify(p)
            counts[c] = counts.get(c, 0) + 1
            f.write('%s  %8d  %-16s  %s\n' % (sha(p), os.path.getsize(p), c, p))
        f.write('\n# totals\n')
        for k in sorted(counts):
            f.write('#   %-16s %d\n' % (k, counts[k]))
    print('%s: %s' % (stem, ', '.join('%s=%d' % (k, counts[k])
                                      for k in sorted(counts))))
PY

# ---- the driver's installed header copies must equal the tool copies ----
#
# THE GAP ROUND 12 LEFT
# ---------------------
# `tools/lucy-obs/RTL812xObsLog.hpp` and `RTL812xObsWrite.hpp` are hashed in the
# manifest. But the driver does not compile those files: `apply-lucy-obs2.py`
# COPIES them into `$DRV/`, and the build includes the COPIES. A change to the
# tool copy that was never re-applied leaves the manifest describing a file the
# build did not use.
#
# So the copies are compared byte for byte, and a difference is a FAILURE --
# not a note. The driver's copy is the one that is compiled; the tool copy is
# the one that is recorded; if they differ, neither statement is true.
if [ -d "$DRV" ]; then
    : > "$OUT/obs-header-identity.txt"
    bad=0
    for pair in "RTL812xObsLog.hpp" "RTL812xObsWrite.hpp"; do
        a="tools/lucy-obs/$pair"
        b="$DRV/$pair"
        if [ ! -f "$b" ]; then
            echo "MISSING-DRIVER-COPY  $pair  ($b)" >> "$OUT/obs-header-identity.txt"
            bad=1
            continue
        fi
        ha=$(shasum -a 256 "$a" | awk '{print $1}')
        hb=$(shasum -a 256 "$b" | awk '{print $1}')
        if [ "$ha" = "$hb" ]; then
            echo "MATCH    $pair  sha256=$ha" >> "$OUT/obs-header-identity.txt"
        else
            echo "MISMATCH $pair" >> "$OUT/obs-header-identity.txt"
            echo "         tool   $a $ha" >> "$OUT/obs-header-identity.txt"
            echo "         driver $b $hb" >> "$OUT/obs-header-identity.txt"
            bad=1
        fi
    done
    cat "$OUT/obs-header-identity.txt"
    if [ "$bad" -ne 0 ]; then
        echo "FAIL: the observation-log headers the driver COMPILES are not" >&2
        echo "      the ones this record hashes. Re-run the patch, or the" >&2
        echo "      manifest describes a file the build did not use." >&2
        exit 1
    fi
fi

# ---- the SDK identity --------------------------------------------------
#
# Not copied (it is gigabytes). Identified by version, path and the hash of the
# archive the platform provides, which is stable per Xcode/CLT install.
{
    echo "# THE SDK -- identified, not copied."
    echo "sdk_path        : $SDK"
    echo "sdk_version     : $SDKVER"
    echo "clang           : $(xcrun clang++ --version | head -1)"
    echo "ld              : $(xcrun ld -v 2>&1 | head -1)"
    echo "xcode_select    : $(xcode-select -p 2>/dev/null || echo '<none>')"
    # The SDK's own settings plist carries the build version the headers were
    # generated for; that is the identity a reader can check.
    for p in "$SDK/SDKSettings.plist" "$SDK/usr/lib/libkmod.a"; do
        if [ -f "$p" ]; then
            echo "$(basename "$p")_sha256 : $(shasum -a 256 "$p" | awk '{print $1}')"
        fi
    done
    if [ -n "$SRC" ] && [ -d "$MSDK" ]; then
        echo "mackernelsdk    : $MSDK"
        # A tree hash: sorted per-file hashes, so the whole SDK directory is
        # identified by content without copying it.
        echo "mackernelsdk_tree_sha256 : $(cd "$MSDK" && find . -type f -print0 |
            sort -z | xargs -0 shasum -a 256 | shasum -a 256 | awk '{print $1}')"
        echo "mackernelsdk_files       : $(cd "$MSDK" && find . -type f | wc -l | tr -d ' ')"
    fi
} > "$OUT/sdk-identity.txt"
cat "$OUT/sdk-identity.txt"

echo
echo "deps.sh: wrote $OUT/{build-commands.txt,*-deps.raw.txt,*-inputs.list,*-inputs.sha256,obs-header-identity.txt,sdk-identity.txt}"
