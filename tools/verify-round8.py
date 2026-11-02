#!/usr/bin/env python3
"""Round-8 offline verification.

Groups, by WHAT THEY PROVE:

  PRODUCTION   the shared core the kext actually includes compiles and its
               regressions pass
  MUTATION     deliberately reintroducing each round-7 defect makes the core
               fail -- without this, a passing test proves nothing about
               whether the test can detect the defect
  DECISION     the analyser catches every injected defect and refuses captures
               that lack the fields it needs
  MODEL        the PTE model agrees with the spec's level numbering
  HYGIENE      the authored files are LF-only and valid UTF-8

WHAT THIS FILE DOES *NOT* PROVE
-------------------------------
It does not prove the kext builds against the real kernel SDK, and it does
not prove anything about the target machine. Those are separate steps:
`tools/build-m1a.sh` on the Mac and the real-machine capture. A green run
here means "the logic is internally consistent and the tests can detect the
defects they claim to guard", nothing more.

Usage:
    py -3 tools/verify-round8.py
Exit code 0 = everything passed.
"""
import glob
import io
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# The DSH session temp area is not writable under workspace-write, so all
# scratch work happens inside the project.
WORK = os.path.join(ROOT, "build-work-verify8")

RESULTS = []


def say(msg):
    print(msg)


def record(cls, name, ok, detail=""):
    RESULTS.append({"cls": cls, "name": name, "ok": bool(ok),
                    "detail": detail})
    status = "PASS" if ok else "FAIL"
    print("  [{}] {:<62} {}".format(cls, name, status))
    if detail and not ok:
        for line in str(detail).splitlines()[:14]:
            print("         {}".format(line))
    return bool(ok)


def run(cmd, cwd=None, timeout=300):
    p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=timeout)
    return p.returncode, p.stdout.decode("utf-8", "replace")


def find_cxx():
    """Locate a host C++ compiler.

    Round 7's verify script used shutil.which("clang++") and silently recorded
    a failure when it was absent -- which is what happened on this host, so
    the PRODUCTION and MUTATION classes never ran at all while the summary
    still looked like a normal report. The compiler here is the LLVM shipped
    with Visual Studio; it needs the STL-version guard disabled because that
    toolchain's libc++ headers are newer than clang 19.
    """
    p = shutil.which("clang++")
    if p:
        return p, []
    for c in (
        r"C:\Program Files\Microsoft Visual Studio\2022\Community"
        r"\VC\Tools\Llvm\bin\clang++.exe",
        r"C:\Program Files\Microsoft Visual Studio\2022\Professional"
        r"\VC\Tools\Llvm\bin\clang++.exe",
        r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise"
        r"\VC\Tools\Llvm\bin\clang++.exe",
        r"C:\Program Files\LLVM\bin\clang++.exe",
    ):
        if os.path.isfile(c):
            return c, ["-D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH"]
    hits = glob.glob(
        r"C:\Program Files\Microsoft Visual Studio\*\*\VC\Tools\Llvm\bin"
        r"\clang++.exe")
    if hits:
        return hits[0], ["-D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH"]
    p = shutil.which("g++")
    if p:
        return p, []
    return None, []


CXX, CXX_EXTRA = find_cxx()


def build(src, out, extra=None):
    cmd = [CXX, "-std=c++17", "-O1", "-Wall", "-Wextra", "-Werror"]
    cmd += CXX_EXTRA
    if extra:
        cmd += extra
    cmd += ["-o", out, src]
    return run(cmd, cwd=ROOT)


# ===========================================================================
# PRODUCTION
# ===========================================================================
def check_production():
    say("\nPRODUCTION - the shared core the kext includes")

    if not CXX:
        record("PRODUCTION", "a host C++ compiler is available", False,
               "no clang++/g++ found; production checks cannot run")
        return

    record("PRODUCTION", "a host C++ compiler is available", True)

    if not os.path.isdir(WORK):
        os.makedirs(WORK)

    for name, src, binary in (
            ("dma-observe-test", "tests/dma-observe-test.cpp",
             "dma-observe-test"),
            ("pte-core-test", "tests/pte-core-test.cpp", "pte-core-test")):
        out_bin = os.path.join(WORK, binary)
        rc, out = build(src, out_bin)
        if rc != 0:
            record("PRODUCTION", "{} compiles".format(name), False, out)
            continue
        record("PRODUCTION", "{} compiles".format(name), True)
        rc, out = run([out_bin], cwd=ROOT)
        ok = (rc == 0)
        summary = ""
        for line in out.splitlines():
            if "passed" in line or "RESULT" in line:
                summary += line + "\n"
        record("PRODUCTION", "{} passes".format(name), ok,
               summary if not ok else summary.strip())


# ===========================================================================
# MUTATION
# ===========================================================================
# Each entry: (description, file, old_text, new_text, test_binary, needle).
# The mutation must make the corresponding test FAIL. If it does not, the
# test cannot detect the defect it claims to guard against.
#
# Round 8's mutations target the defects ROUND 7 introduced or left, because
# those are the ones this round's code is supposed to have removed.
MUTATIONS = [
    (
        "round-7 defect 5: mark every non-zero TX address in-flight again",
        "kext/amd_iommu_dma_observe.hpp",
        """        // Lifecycle is decided against the END-of-window close pointer: the
        // question is "has the device handed this descriptor back by now".
        // Compare CUMULATIVE indices, not slot numbers.
        const bool doneAtEnd = txCumCompleted(c, cloAfter, mask);""",
        """        // MUTATION: round 7 marked everything in-flight.
        const bool doneAtEnd = false;""",
        "dma-observe-test",
        "FAIL",
    ),
    (
        "round-7 defect 6: report a snapshot hit as a completed range",
        "kext/amd_iommu_dma_observe.hpp",
        """    if (set.containsLifecycle(addr, LIFE_SNAPSHOT, &f.purpose)) {
        f.own = OWN_IN_SNAPSHOT_SET;""",
        """    if (set.containsLifecycle(addr, LIFE_SNAPSHOT, &f.purpose)) {
        f.own = OWN_IN_COMPLETED_SET;""",
        "dma-observe-test",
        "FAIL",
    ),
    (
        "round-7 defect 7: a gap in a snapshot is a gap in the window",
        "kext/amd_iommu_dma_observe.hpp",
        """    if (set.exact() && coverage == COV_WINDOW) {
        f.own = OWN_IN_ENVELOPE_GAP;""",
        """    if (set.exact()) {
        f.own = OWN_IN_ENVELOPE_GAP;""",
        "dma-observe-test",
        "FAIL",
    ),
    (
        "round-7 defect 8: one coverage value for every path",
        "kext/amd_iommu_dma_observe.hpp",
        """        if (!allPathsCovered) {
            // Window coverage exists, but only for some paths. Saying
            // "outside every DMA range the device used" would generalise a
            // TX-only result to RX, the rings and the stats buffer.
            f.own = OWN_TX_WINDOW_ABSENT;""",
        """        if (false) {
            f.own = OWN_TX_WINDOW_ABSENT;""",
        "dma-observe-test",
        "FAIL",
    ),
    (
        "round-7 defect 9: a register name is enough to trust ring contents",
        "kext/amd_iommu_dma_observe.hpp",
        """    f.ok = (f.decoded > 0) && (f.ringEndAtLast != 0);""",
        """    f.ok = true;   // MUTATION: no fingerprint check at all""",
        "dma-observe-test",
        "FAIL",
    ),
    (
        "round-6 defect 1: filter recording by the map limit again",
        "kext/amd_iommu_dma_observe.hpp",
        """        growEnvelope(base, len);
        mergedTotal++;""",
        """        if (readVerdict(base, len, defaultMapPolicy()) != RD_OK) return false;
        growEnvelope(base, len);
        mergedTotal++;""",
        "dma-observe-test",
        "FAIL",
    ),
    (
        "round-6 defect 2: stop growing the envelope once the set is full",
        "kext/amd_iommu_dma_observe.hpp",
        """        growEnvelope(base, len);
        mergedTotal++;
        if (n >= MAX_RANGES) {
            droppedCount++;""",
        """        mergedTotal++;
        if (n >= MAX_RANGES) {
            droppedCount++;""",
        "dma-observe-test",
        "FAIL",
    ),
    (
        "round-6 defect 4: close pointer delta back to ring modulo",
        "kext/amd_iommu_dma_observe.hpp",
        """static inline u32 cloPtrDelta(u32 before, u32 after, u32 mask) {
    if (mask == 0) return 0;
    return (u32)((after - before) & mask);
}""",
        """static inline u32 cloPtrDelta(u32 before, u32 after, u32 mask) {
    if (mask == 0) return 0;
    return (u32)((after - before) & 1023u);   // MUTATION: ring modulo
}""",
        "dma-observe-test",
        "FAIL",
    ),
    (
        "round-5 defect: classify by the map limit before set membership",
        "kext/amd_iommu_dma_observe.hpp",
        """    if (set.containsLive(addr, &f.purpose)) {
        f.own = OWN_IN_LIVE_SET;""",
        """    if (addr >= policy.limit) {
        f.own = OWN_OUTSIDE_ENVELOPE;
        f.reason = "MUTATION: above the map limit, therefore not device memory";
        return f;
    }
    if (set.containsLive(addr, &f.purpose)) {
        f.own = OWN_IN_LIVE_SET;""",
        "dma-observe-test",
        "FAIL",
    ),
    (
        "round-8 defect: a reused slot is not counted as overwritten",
        "kext/amd_iommu_dma_observe.hpp",
        """        if (!txSlotStillHolds(c, tailAfter, ringSize)) {
            s.overwritten++;
            continue;
        }""",
        """        if (!txSlotStillHolds(c, tailAfter, ringSize)) {
            continue;   // MUTATION: silently skip the lost descriptor
        }""",
        "dma-observe-test",
        "FAIL",
    ),
    (
        "round-8 defect: an undecoded length no longer blocks an exact claim",
        "kext/amd_iommu_dma_observe.hpp",
        """    bool exactBounded() const {
        return exact() && savedLenUnknown == 0;
    }""",
        """    bool exactBounded() const {
        return exact();   // MUTATION: ignore undecoded lengths
    }""",
        "dma-observe-test",
        "FAIL",
    ),
    (
        "round-8 defect: the weakest path coverage reports window-complete",
        "kext/amd_iommu_dma_observe.hpp",
        """    u32 weakest() const {
        u32 w = COV_WINDOW;
        const u32 v[5] = { txRing, rxRing, txBuf, rxBuf, stat };
        for (int i = 0; i < 5; i++) if (v[i] < w) w = v[i];
        return w;
    }""",
        """    u32 weakest() const {
        return txBuf;   // MUTATION: report the TX path for every path
    }""",
        "dma-observe-test",
        "FAIL",
    ),
    (
        "round-8 defect: the submit pointer itself counts as written",
        "kext/amd_iommu_dma_observe.hpp",
        """    const u32 lastWritten = tailAfter - 1;""",
        """    const u32 lastWritten = tailAfter;   // MUTATION: off by one""",
        "dma-observe-test",
        "FAIL",
    ),
    (
        "model defect: NextLevel=7 encodes the level's own default size",
        "kext/amd_iommu_pte_core.hpp",
        """    if (ps <= lo) {""",
        """    if (ps < lo) {   // MUTATION: allow the illegal equal case""",
        "pte-core-test",
        "FAIL",
    ),
]


def check_mutations():
    say("\nMUTATION - deliberately reintroduce each defect")

    if not CXX:
        record("MUTATION", "a host C++ compiler is available", False,
               "no compiler; mutation checks cannot run")
        return

    if not os.path.isdir(WORK):
        os.makedirs(WORK)

    for desc, relpath, old, new, binary, needle in MUTATIONS:
        target = os.path.join(ROOT, relpath)
        with io.open(target, "r", encoding="utf-8", newline="") as f:
            original = f.read()

        if original.count(old) != 1:
            record("MUTATION", desc, False,
                   "anchor found {} times in {} (must be exactly 1)".format(
                       original.count(old), relpath))
            continue

        mutated = original.replace(old, new, 1)
        backup = target + ".mutbak"
        try:
            with io.open(backup, "w", encoding="utf-8", newline="") as f:
                f.write(original)
            with io.open(target, "w", encoding="utf-8", newline="") as f:
                f.write(mutated)

            src = os.path.join(ROOT, "tests",
                               "dma-observe-test.cpp" if binary ==
                               "dma-observe-test" else "pte-core-test.cpp")
            out_bin = os.path.join(WORK, binary + "-mut.exe")
            rc, out = build(src, out_bin)
            if rc != 0:
                # A mutation that does not compile still demonstrates the
                # mutation was applied, but it does not prove the TEST can
                # catch the defect. Treat it as a failure of the harness.
                record("MUTATION", desc, False,
                       "mutation did not compile:\n{}".format(out[:2000]))
                continue
            rc, out = run([out_bin], cwd=ROOT)
            caught = (rc != 0) and (needle in out)
            record("MUTATION", desc, caught,
                   "" if caught else
                   "the mutated core was NOT caught by the test "
                   "(rc={}):\n{}".format(rc, out[-2000:]))
        finally:
            if os.path.isfile(backup):
                with io.open(backup, "r", encoding="utf-8", newline="") as f:
                    restored = f.read()
                with io.open(target, "w", encoding="utf-8", newline="") as f:
                    f.write(restored)
                os.remove(backup)


# ===========================================================================
# DECISION
# ===========================================================================
def check_decision():
    say("\nDECISION - the analyser and its own regressions")

    rc, out = run([sys.executable,
                   os.path.join(ROOT, "tools", "test-analyzer8.py")], cwd=ROOT)
    ok = (rc == 0)
    summary = ""
    for line in out.splitlines():
        if "passed" in line or "RESULT" in line:
            summary += line + "\n"
    record("DECISION", "analyser negative regressions", ok,
           summary if not ok else summary.strip())

    # Historical captures that cannot be analysed by the round-8 analyser
    # must be refused, not silently judged against the wrong check set.
    for stamp, why in (
            ("20261031-180500", "round 5: no round-7 or round-8 fields"),
            ("20261031-201400", "round 6: no round-7 or round-8 fields"),
            ("20261031-165500", "round 4: no device-DMA observation"),
            ("20261031-064350", "round 7: no round-8 fields")):
        path = os.path.join(ROOT, "docs", "evidence", stamp, "props.txt")
        if not os.path.isfile(path):
            record("DECISION", "capture {} present".format(stamp), False,
                   "not found: " + path)
            continue
        rc, out = run([sys.executable,
                       os.path.join(ROOT, "tools", "analyze-round8.py"),
                       path], cwd=ROOT)
        record("DECISION", "refuses {} ({})".format(stamp, why), rc == 2,
               "exit {} (wanted 2)".format(rc) if rc != 2 else "")


# ===========================================================================
# MODEL
# ===========================================================================
def check_model():
    say("\nMODEL - the PTE model agrees with the spec")

    src = io.open(os.path.join(ROOT, "kext", "amd_iommu_pte_core.hpp"),
                  "r", encoding="utf-8").read()
    # Level numbering is 1-based: level 2's default page size is 2 MiB.
    record("MODEL", "level numbering is the spec's 1-based numbering",
           "LEVEL_4K   = 1" in src and "LEVEL_2M   = 2" in src and
           "LEVEL_1G   = 3" in src and "LEVEL_512G = 4" in src)
    # NextLevel=0 is the default leaf; makeDefaultLeaf must not encode 7.
    m = re.search(r"inline u64 makeDefaultLeaf\(.*?\n\}", src, re.S)
    body = m.group(0) if m else ""
    record("MODEL", "default leaf does not encode NextLevel",
           "levelEnc" not in body and "NEXT_LEVEL_LARGE" not in body,
           body[:400])


# ===========================================================================
# HYGIENE
# ===========================================================================
AUTHORED = [
    "kext/AMDMapperProbe.cpp",
    "kext/AMDMapperProbe.hpp",
    "kext/AMDMapperProbe-Info.plist",
    "kext/amd_iommu_dma_observe.hpp",
    "kext/amd_iommu_pte_core.hpp",
    "tests/dma-observe-test.cpp",
    "tests/pte-core-test.cpp",
    "tools/analyze-round8.py",
    "tools/test-analyzer8.py",
    "tools/verify-round8.py",
]


def check_hygiene():
    say("\nHYGIENE - the authored files are LF-only and valid UTF-8")

    bad_cr = []
    bad_utf = []
    for rel in AUTHORED:
        path = os.path.join(ROOT, rel)
        if not os.path.isfile(path):
            bad_utf.append("{}: missing".format(rel))
            continue
        data = io.open(path, "rb").read()
        if b"\r" in data:
            bad_cr.append("{}: {} CR byte(s)".format(rel, data.count(b"\r")))
        try:
            data.decode("utf-8")
        except UnicodeDecodeError as e:
            bad_utf.append("{}: {}".format(rel, e))

    record("HYGIENE", "every authored file is LF-only", not bad_cr,
           "; ".join(bad_cr[:6]))
    record("HYGIENE", "every authored file is valid UTF-8", not bad_utf,
           "; ".join(bad_utf[:6]))


def main():
    print("Round-8 offline verification")
    print("=" * 78)
    print("root: {}".format(ROOT))
    print("cxx : {}".format(CXX or "NOT FOUND"))
    if CXX_EXTRA:
        print("      (extra flags: {})".format(" ".join(CXX_EXTRA)))

    if not os.path.isdir(WORK):
        os.makedirs(WORK)

    check_production()
    check_mutations()
    check_decision()
    check_model()
    check_hygiene()

    print("\n" + "=" * 78)
    classes = {}
    for r in RESULTS:
        c = classes.setdefault(r["cls"], {"pass": 0, "fail": 0})
        if r["ok"]:
            c["pass"] += 1
        else:
            c["fail"] += 1
    for cls in ("PRODUCTION", "MUTATION", "DECISION", "MODEL", "HYGIENE"):
        if cls not in classes:
            continue
        c = classes[cls]
        print("  {:<12} {}/{}".format(cls, c["pass"], c["pass"] + c["fail"]))
    total_fail = sum(c["fail"] for c in classes.values())
    total = sum(c["pass"] + c["fail"] for c in classes.values())
    print()
    if total_fail:
        print("RESULT: {} of {} check(s) FAILED".format(total_fail, total))
        return 1
    print("RESULT: ALL {} CHECKS PASS".format(total))
    return 0


if __name__ == "__main__":
    sys.exit(main())
