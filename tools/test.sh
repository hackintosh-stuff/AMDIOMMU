#!/bin/sh
# Userspace tests only. No network, installation, or hardware access.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
python3 "$ROOT/tools/check_source.py"
WORK=$(mktemp -d "$ROOT/test-work.XXXXXX")
CXX=${CXX:-clang++}
# Sanitizers are enabled by default; do not silently retry without them.
SAN_FLAGS=""
case "${SANITIZE:-1}" in
    1) SAN_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" ;;
    0) ;;
    *) printf 'SANITIZE must be 0 or 1\n' >&2; exit 2 ;;
esac
printf 'TEST_COMPILER=%s\nSANITIZER_FLAGS=%s\n' "$CXX" "$SAN_FLAGS"
# Intentional splitting of fixed sanitizer flags, not user-provided code.
"$CXX" -std=c++17 -Wall -Wextra -Wpedantic -Werror -O1 -g $SAN_FLAGS \
    -I "$ROOT/include" "$ROOT/src/IdentityMap.cpp" "$ROOT/src/Ivrs.cpp" \
    "$ROOT/src/IvrsTopology.cpp" \
    "$ROOT/tests/IdentityTests.cpp" "$ROOT/tests/IvrsTests.cpp" \
    "$ROOT/tests/TopologyTests.cpp" \
    -o "$WORK/offline-tests"
"$WORK/offline-tests"
"$CXX" -std=c++17 -Wall -Wextra -Wpedantic -Werror -O1 -g $SAN_FLAGS \
    -I "$ROOT/include" "$ROOT/src/Ivrs.cpp" "$ROOT/tools/ivrs-inspect.cpp" \
    -o "$WORK/ivrs-inspect"
python3 "$ROOT/tests/InspectorSmoke.py" "$WORK/ivrs-inspect" "$WORK" "$ROOT/fixtures"

# ---- the kext's own cores, tested from the same files the kext compiles ----
#
# WHY THIS WAS MISSING
# --------------------
# tools/test.sh only ever built the userspace IVRS/identity code. The two cores
# that actually decide the experiment's verdicts -- amd_iommu_pte_core.hpp and
# amd_iommu_dma_observe.hpp -- were tested by separate one-off binaries that
# nothing invoked. Round 10 reported "462 host regressions" from
# tests/dma-observe-test.cpp, but that number came from running the binary by
# hand; the project's own test entry point never ran it.
#
# A count that comes from a manual step is not a regression suite: it cannot
# fail a build. So both cores, and the observation log's write protocol, are
# now part of this script.
printf '\n== kext core regressions ==\n'
"$CXX" -std=c++17 -Wall -Wextra -Wpedantic -Werror -O1 -g $SAN_FLAGS \
    -I "$ROOT/include" -I "$ROOT/kext" \
    "$ROOT/src/IdentityMap.cpp" "$ROOT/src/Ivrs.cpp" \
    "$ROOT/src/IvrsTopology.cpp" "$ROOT/tests/dma-observe-test.cpp" \
    -o "$WORK/dma-observe-test"
"$WORK/dma-observe-test"

"$CXX" -std=c++17 -Wall -Wextra -Wpedantic -Werror -O1 -g $SAN_FLAGS \
    -I "$ROOT/include" -I "$ROOT/kext" "$ROOT/tests/pte-core-test.cpp" \
    -o "$WORK/pte-core-test"
"$WORK/pte-core-test"

# ---- R70 S1: the capacity model ------------------------------------------
#
# The ordinary mapper's arena is now sized by a profile instead of compile-time
# constants. Two things must therefore hold, and both are checked here rather
# than trusted:
#
#   1. the runtime-sized allocator is indistinguishable from the compile-time
#      one it replaced (the legacy profile has to stay byte-compatible with
#      R67-2), and
#   2. the profile table and the arena arithmetic match the documented values,
#      so a widened window is a reviewed number, not an accident.
printf '\n== R70 capacity model ==\n'
"$CXX" -std=c++17 -Wall -Wextra -Wpedantic -Werror -O1 -g $SAN_FLAGS \
    -I "$ROOT/kext" "$ROOT/tests/r70-capacity-test.cpp" \
    -o "$WORK/r70-capacity-test"
"$WORK/r70-capacity-test"

# ---- round 12: the two cores that decide the verdict --------------------
#
# WHY THESE ARE HERE AND NOT IN A ONE-OFF BINARY
# ----------------------------------------------
# Round 10 reported "462 host regressions" from tests/dma-observe-test.cpp, but
# that number came from running the binary by hand; the project's own entry
# point never ran it, so it could not fail a build. The same mistake would be
# easy to repeat with the two new cores, which are the ones that now decide
# whether a run is a success candidate:
#
#   amd_iommu_bizwalk_core.hpp  walks every byte of every business range
#   obsEvidenceGate()           decides whether the evidence is sufficient
#
# Both are headers the kext compiles, so these binaries exercise production
# logic rather than a restatement of it.
printf '\n== round-12 cores ==\n'
"$CXX" -std=c++17 -Wall -Wextra -Wpedantic -Werror -O1 -g $SAN_FLAGS \
    -I "$ROOT/kext" "$ROOT/tests/bizwalk-core-test.cpp" \
    -o "$WORK/bizwalk-core-test"
"$WORK/bizwalk-core-test"

"$CXX" -std=c++17 -Wall -Wextra -Wpedantic -Werror -O1 -g $SAN_FLAGS \
    -I "$ROOT/kext" "$ROOT/tests/evidence-gate-test.cpp" \
    -o "$WORK/evidence-gate-test"
"$WORK/evidence-gate-test"

# The gate is only worth anything if the PRODUCTION verdict consults it. That
# is a property of the source, so it is checked by reading the source.
python3 "$ROOT/tools/r12/verify-gate-wiring.py"

# ---- round 14: the RX posted-buffer set --------------------------------
#
# The set is the round's actual subject, so its test is part of the entry point
# rather than a binary run by hand. It is built with TSan for the same reason
# obs-write-test is: the rearm ring is written on the RX path while the
# watchdog publishes, and that pair is what has to be race-free.
printf '\n== round-14 RX set ==\n'
"$CXX" -std=c++17 -Wall -Wextra -Wpedantic -Werror -O1 -g -pthread \
    -fsanitize=thread -I "$ROOT/kext" -I "$ROOT/tools/lucy-obs" \
    "$ROOT/tests/rxpost-test.cpp" -o "$WORK/rxpost-test"
"$WORK/rxpost-test"

# The same 160-byte header is declared THREE times (driver structs, probe byte
# offsets, test). A drift does not fail to compile -- it decodes `capacity` out
# of the middle of `addr` and yields plausible wrong ranges. So the three are
# compared mechanically.
python3 "$ROOT/tools/r14/check-rxpost-layout.py"

# And the geometry assertion must be SENSITIVE. Round 14's first real-machine run
# failed with `ragged-rearm-body` because publishCopy() started its copy at
# offset 0; the host test had missed it because its helper used the same wrong
# origin on both sides. Adding an assertion is not enough -- it has to fail on
# the broken code. This reintroduces that one-line defect and requires the
# geometry checks to catch it.
python3 "$ROOT/tools/r14/verify-rxpost-geometry.py"

# Round 14's second real-machine run lost its RX blob because the probe published
# the OSData and then a status STRING under the SAME property name; IOKit
# replaces a property, so the blob vanished with no error. This scans every
# setProperty call site for a name carrying two different kinds of value, and the
# sensitivity check proves the scanner can actually see one.
python3 "$ROOT/tools/r14/verify-property-names.py"
python3 "$ROOT/tools/r14/verify-property-names-sensitivity.py"

# Round 14's run 5 PANICKED in rxpostRecordRearm because kRxPostRegionBytes was
# defined as kRxPostSnapshotMax -- one slot array too small -- while rxpostInit()
# places the rearm ring after TWO slot arrays. The tail of the ring fell outside
# the IOBufferMemoryDescriptor's mapping and the write faulted minutes later.
# This check restores that exact definition and requires the build to reject it.
python3 "$ROOT/tools/r14/verify-region-size.py"

# The write protocol needs threads, so it is built with -pthread and without
# ASan (TSan and ASan cannot be combined). It is run under TSan instead, which
# is the tool that would actually catch a data race in it.
#
# ROUND 12: the include path is explicit (-I tools/lucy-obs) because the test
# includes the protocol header by BARE NAME. That is deliberate: the same test
# source is compiled against round-10 and round-11 headers by
# tools/r11/verify-write-protocol.py, and a relative include would silently
# resolve to the shipped header in every build, making the substitution a no-op.
"$CXX" -std=c++17 -Wall -Wextra -Wpedantic -Werror -O1 -g -pthread \
    -fsanitize=thread -I "$ROOT/kext" -I "$ROOT/tests" \
    -I "$ROOT/tools/lucy-obs" \
    "$ROOT/tests/obs-write-test.cpp" -o "$WORK/obs-write-test"
"$WORK/obs-write-test"

# The protocol header duplicates four offsets from the wire header (it cannot
# include it: the host test has no IOKit). That duplication is checked against
# the real struct definitions rather than trusted.
python3 "$ROOT/tools/r11/check-obs-layout.py"

# ROUND 13: the `wrapped` counter had two authorities and only one was
# published. Fixing tools/lucy-obs/RTL812xObsWrite.hpp alone changes nothing --
# the defect was in the DRIVER's publish path, which lives in
# tools/apply-lucy-obs2.py as a template. So this compiles the REAL obsPublish()
# body, extracted from that template, against the real header, and requires the
# published `wrapped` to equal the number of slots actually displaced. It also
# requires the round-12 variant to FAIL the same assertion, so the check is
# known to be sensitive to the defect.
python3 "$ROOT/tools/r13/verify-wrapped-publish.py"

# The round-11 split checker (tools/r11/verify-split.py) was retired here: its
# invariants (original-line markers, a single metaclass block, production
# definitions for Debug-only methods) describe the pre-refactor tree and can no
# longer distinguish a real split defect from later, unrelated edits.

# Round 12: the write protocol is only verified if the SAME test source FAILS
# against the round-10 and round-11 headers. This rebuilds the real test binary
# three times and requires exactly that, plus a TSan run of the shipped header.
python3 "$ROOT/tools/r11/verify-write-protocol.py"

# ---- round 12: the scripts that are only ever READ ---------------------
#
# build-record.sh and en2-run.sh are the two places where a defect costs a
# reboot or a false record rather than a failed build. Neither can be verified
# by reading it, and neither can be verified by running it against the real
# machine. So both are driven with command stubs, and both are compared against
# a FROZEN earlier version (or a single-point mutation of one) so that "the
# cases pass" means "the old defect is caught", not merely "the script exits 0".
printf '\n== round-12 scripts ==\n'
python3 "$ROOT/tools/r12/verify-build-record.py"
python3 "$ROOT/tools/r12/verify-en2run.py"

# ---- round 13: the four defects that survived round 12's own suite ------
#
# Each of these is a script whose ONLY job is to catch a defect that round 12
# shipped while its own tests were green. They are listed separately from the
# round-12 block because the report states them separately.
printf '\n== round-13 checks ==\n'
# The control schema and the control fixture must agree with the PRODUCTION
# branch, not with each other. This reads the branch out of the kext source.
python3 "$ROOT/tools/r13/verify-control-shape.py"
# record-loaded.sh must not report "not loaded" when its own query failed.
python3 "$ROOT/tools/r13/verify-record-loaded.py"
# The patch writes obsWrite()/obsPublish() by TEXT SUBSTITUTION, so editing the
# template does nothing to an already-patched tree. This needs the REAL upstream
# tarball and REFUSES (exit 2) without it, rather than reporting a weaker result
# as the same one.
python3 "$ROOT/tools/r13/verify-patch-freshness.py" || {
    rc=$?
    if [ "$rc" -ne 2 ]; then exit "$rc"; fi
    printf '  (patch freshness REFUSED: no upstream tarball on this host)\n'
    printf '  This is a REFUSAL, not a pass. Run tools/test.sh on the Mac\n'
    printf '  build host for the full gate.\n'
}
# The build is NOT byte-reproducible for the probe. Measure it, and record what
# the measurement says, instead of repeating round 12's untested claim.
python3 "$ROOT/tools/r13/verify-reproducibility.py"

# The analyser is the gate on the evidence. Its positive case is the real
# round-11 archive; its negative cases are mutations of that archive. Both are
# required: a suite that only rejects would pass on an analyser that rejects
# everything.
#
# The fixture is generated here rather than checked in, because a checked-in
# fixture silently goes stale when the schema changes -- and a stale fixture
# makes the negative suite test a shape the analyser no longer accepts.
printf '\n== round-12 analyser ==\n'
FIXTURE_DIR="$WORK/fixture-r12"
python3 "$ROOT/tools/r11/make-fixture.py" "$FIXTURE_DIR" > /dev/null
CONTROL_DIR="$WORK/fixture-r12-control"
python3 "$ROOT/tools/r12/make-control-fixture.py" "$CONTROL_DIR" > /dev/null
REAL_CAPTURE="$ROOT/docs/evidence/20261101-014200"
python3 "$ROOT/tools/r12/test-analyzer12.py" "$REAL_CAPTURE" "$FIXTURE_DIR"
python3 "$ROOT/tools/r12/verify-mode-schema.py" "$CONTROL_DIR" "$REAL_CAPTURE"

# The two round-12 archives must still be judged the way round 12 judged them:
# the passing one passes, the gate-refused one is still refused. A regression in
# either direction means the round-13 hardening changed a verdict rather than
# tightened a check.
printf '\n== round-12 archive replay ==\n'
python3 "$ROOT/tools/r13/replay-archives.py"

printf 'TEST_OK=%s\nINSPECTOR=%s\n' "$WORK/offline-tests" "$WORK/ivrs-inspect"
printf 'CORE_OK=%s %s %s %s %s %s %s\n' "$WORK/dma-observe-test" \
       "$WORK/pte-core-test" "$WORK/obs-write-test" \
       "$WORK/bizwalk-core-test" "$WORK/evidence-gate-test" \
       "$WORK/rxpost-test" "$WORK/r70-capacity-test"
(cd "$ROOT" && shasum -a 256 include/amd_iommu/*.hpp src/*.cpp \
    kext/amd_iommu_*.hpp kext/AMDMapperProbe*.cpp kext/AMDMapperProbe*.hpp \
    tools/lucy-obs/*.hpp \
    tests/*.cpp tests/InspectorSmoke.py tools/test.sh tools/ivrs-inspect.cpp \
    tools/check_source.py tools/r11/*.py tools/r12/*.py tools/r13/*.py \
    tools/r14/*.py fixtures/*.bin) \
    > "$WORK/test-source-manifest.sha256"
printf '%s\n' "$WORK" > "$ROOT/latest-tests.txt"

