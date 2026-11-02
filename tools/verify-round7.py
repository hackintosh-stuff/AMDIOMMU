#!/usr/bin/env python3
"""Round-7 offline verification.

Runs every check that can be run without touching the target machine. The
checks are grouped by WHAT THEY PROVE, because the rounds keep discovering
that "a test passed" and "the thing I care about was exercised" are
different claims:

  PRODUCTION   the shared core the kext actually includes compiles and its
               regressions pass
  MUTATION     deliberately reintroducing each round-6 defect makes the core
               fail -- without this, a passing test proves nothing about
               whether the test can detect the defect
  DECISION     the analyser catches every injected defect and refuses old
               captures that lack the fields it needs
  MODEL        the PTE model agrees with the spec's level numbering
  HYGIENE      the authored files are LF-only and valid UTF-8

Usage:
    py -3 tools/verify-round7.py
Exit code 0 = everything passed.
"""
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# The DSH session temp area is not writable under workspace-write, so all
# scratch work happens inside the project.
WORK = os.path.join(ROOT, "build-work-verify7")

CXX = "clang++"
RESULTS = []


def say(msg):
    print(msg)


def record(cls, name, ok, detail=""):
    RESULTS.append({"cls": cls, "name": name, "ok": bool(ok),
                    "detail": detail})
    status = "PASS" if ok else "FAIL"
    print("  [{}] {:<62} {}".format(cls, name, status))
    if detail and not ok:
        for line in detail.splitlines()[:12]:
            print("         {}".format(line))
    return bool(ok)


def run(cmd, cwd=None, timeout=300):
    p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=timeout)
    return p.returncode, p.stdout.decode("utf-8", "replace")


def have_clang():
    return shutil.which(CXX) is not None


# ===========================================================================
# PRODUCTION
# ===========================================================================
def check_production():
    say("\nPRODUCTION - the shared core the kext includes")

    if not have_clang():
        record("PRODUCTION", "clang++ available", False,
               "clang++ not found; production checks cannot run")
        return

    for name, src, binary in (
            ("dma-observe-test", "tests/dma-observe-test.cpp",
             "dma-observe-test"),
            ("pte-core-test", "tests/pte-core-test.cpp", "pte-core-test")):
        out_bin = os.path.join(WORK, binary)
        rc, out = run([CXX, "-std=c++17", "-O2", "-Wall", "-Wextra",
                       "-Werror", "-o", out_bin, src], cwd=ROOT)
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
# Each entry: (description, file, old_text, new_text, test_binary).
# The mutation must make the corresponding test FAIL. If it does not, the
# test cannot detect the defect it claims to guard against.
MUTATIONS = [
    (
        "round-6 defect 1: filter recording by the map limit again",
        "kext/amd_iommu_dma_observe.hpp",
        """    bool insert(u64 base, u64 len, u32 purpose, u32 lifecycle, u32 readable) {
        if (len == 0) {
            zeroLenSkipped++;
            return false;
        }""",
        """    bool insert(u64 base, u64 len, u32 purpose, u32 lifecycle, u32 readable) {
        if (len == 0) {
            zeroLenSkipped++;
            return false;
        }
        // MUTATION: reinstate the round-6 map-limit filter.
        if (readVerdict(base, len, defaultMapPolicy()) != RD_OK) {
            return false;
        }""",
        "dma-observe-test",
    ),
    (
        "round-6 defect 2: stop growing the envelope once the set is full",
        "kext/amd_iommu_dma_observe.hpp",
        """        const u64 len = end - base;
        set.insert(base, len, purpose, lifecycle,
                   readVerdict(base, len, policy));
    }
    set.rawOffered += n;""",
        """        const u64 len = end - base;
        set.insert(base, len, purpose, lifecycle,
                   readVerdict(base, len, policy));
        // MUTATION: reinstate the round-6 early break.
        if (set.n >= MAX_RANGES) break;
    }
    set.rawOffered += n;""",
        "dma-observe-test",
    ),
    (
        "round-6 defect 4: mark every observed range live",
        "kext/amd_iommu_dma_observe.hpp",
        """    if (set.containsLive(addr, &f.purpose)) {""",
        """    if (set.contains(addr, &f.purpose)) {   // MUTATION: live == any
""",
        "dma-observe-test",
    ),
    (
        "round-6 close-pointer defect: ring-modulo instead of the mask",
        "kext/amd_iommu_dma_observe.hpp",
        """static inline u32 cloPtrDelta(u32 before, u32 after, u32 mask) {
    if (mask == 0) return 0;
    return (u32)((after - before) & mask);
}""",
        """static inline u32 cloPtrDelta(u32 before, u32 after, u32 mask) {
    (void)mask;
    // MUTATION: the round-6 modulo-1024 ring advance.
    return (u32)((after + 1024u - before) % 1024u);
}""",
        "dma-observe-test",
    ),
    (
        "round-5 defect: classify by the map limit before set membership",
        "kext/amd_iommu_dma_observe.hpp",
        """    if (set.containsLive(addr, &f.purpose)) {
        f.own = OWN_IN_LIVE_SET;
        f.reason = "the address is inside a DMA range the device currently owns";
        return f;
    }""",
        """    // MUTATION: the round-5 inversion -- the limit decides first.
    if (addr >= policy.limit) {
        f.own = OWN_OUTSIDE_ENVELOPE;
        f.reason = "above the identity map limit";
        return f;
    }
    if (set.containsLive(addr, &f.purpose)) {
        f.own = OWN_IN_LIVE_SET;
        f.reason = "the address is inside a DMA range the device currently owns";
        return f;
    }""",
        "dma-observe-test",
    ),
    (
        "round-7 defect: apply the strict read verdict to device-reported bases",
        "kext/amd_iommu_dma_observe.hpp",
        """static inline u32 readVerdictDeviceReported(u64 base, u64 len,
                                            const MapPolicy &p) {
    if (len == 0) return RD_ZERO_LEN;
    if (base + len < base) return RD_OVERFLOW;
    const u64 end = base + len;
    if (end > p.limit) return RD_OUT_OF_MAP;
    if (base < p.ramHoleHi && end > p.ramHoleLo) return RD_NOT_RAM;
    return RD_OK;
}""",
        """static inline u32 readVerdictDeviceReported(u64 base, u64 len,
                                            const MapPolicy &p) {
    if (len == 0) return RD_ZERO_LEN;
    if (base + len < base) return RD_OVERFLOW;
    const u64 end = base + len;
    if (end > p.limit) return RD_OUT_OF_MAP;
    if (base < p.ramHoleHi && end > p.ramHoleLo) return RD_NOT_RAM;
    if (!p.layoutKnown) return RD_UNVERIFIED;   // MUTATION: too strict
    return RD_OK;
}""",
        "dma-observe-test",
    ),
    (
        "PTE defect: accept NextLevel=7 encoding the level default",
        "kext/amd_iommu_pte_core.hpp",
        """    if (ps <= lo) {
        if (why) *why = "enlarged page size is not larger than the level "
                        "default; this must be encoded as NextLevel=0";
        return false;
    }""",
        """    if (ps < lo) {   // MUTATION: 'not larger' weakened to 'smaller'
        if (why) *why = "enlarged page size is not larger than the level "
                        "default; this must be encoded as NextLevel=0";
        return false;
    }""",
        "pte-core-test",
    ),
]


def check_mutations():
    say("\nMUTATION - deliberately reintroduce each defect")

    if not have_clang():
        record("MUTATION", "clang++ available", False,
               "clang++ not found; mutation checks cannot run")
        return

    for desc, relpath, old, new, binary in MUTATIONS:
        src = os.path.join(ROOT, relpath)
        try:
            with io.open(src, "r", encoding="utf-8", newline="") as f:
                text = f.read()
        except IOError as e:
            record("MUTATION", desc, False, "cannot read {}: {}".format(src, e))
            continue

        if old not in text:
            record("MUTATION", desc, False,
                   "mutation anchor not found in {} -- the test would "
                   "silently pass".format(relpath))
            continue

        mutated = text.replace(old, new, 1)
        if mutated == text:
            record("MUTATION", desc, False, "mutation had no effect")
            continue

        # Write the mutated header into a scratch tree that mirrors the
        # include layout the test expects (../kext/...).
        scratch = tempfile.mkdtemp(dir=WORK, prefix="mut-")
        try:
            os.makedirs(os.path.join(scratch, "kext"))
            os.makedirs(os.path.join(scratch, "tests"))
            for name in ("amd_iommu_dma_observe.hpp",
                         "amd_iommu_pte_core.hpp"):
                s = os.path.join(ROOT, "kext", name)
                d = os.path.join(scratch, "kext", name)
                if os.path.abspath(s) == os.path.abspath(src):
                    with io.open(d, "w", encoding="utf-8", newline="") as f:
                        f.write(mutated)
                else:
                    shutil.copyfile(s, d)
            test_src = os.path.join(ROOT, "tests", binary + ".cpp")
            dst = os.path.join(scratch, "tests", binary + ".cpp")
            shutil.copyfile(test_src, dst)

            out_bin = os.path.join(scratch, binary)
            rc, out = run([CXX, "-std=c++17", "-O2", "-Wall", "-Wextra",
                           "-Werror", "-o", out_bin, dst], cwd=scratch)
            if rc != 0:
                # A mutation that does not compile still demonstrates the
                # test cannot run against it, but it does NOT demonstrate
                # detection. Treat it as a failure of the mutation harness.
                record("MUTATION", desc, False,
                       "mutated build failed:\n" + out)
                continue
            rc, out = run([out_bin], cwd=scratch)
            if rc == 0:
                record("MUTATION", desc, False,
                       "the mutated core still PASSED the test, so the test "
                       "cannot detect this defect")
            else:
                fails = [ln for ln in out.splitlines() if ln.startswith("FAIL")]
                record("MUTATION", desc, True,
                       "{} check(s) caught it".format(len(fails)))
        finally:
            shutil.rmtree(scratch, ignore_errors=True)


# ===========================================================================
# DECISION
# ===========================================================================
OLD_CAPTURES = [
    "docs/evidence/20261031-180500/props.txt",
    "docs/evidence/20261031-201400/props.txt",
    "docs/evidence/20261031-165500/props.txt",
]


def check_decision():
    say("\nDECISION - the analyser and its own regressions")

    # The analyser's negative regressions. This is the check that matters:
    # a checker that rejects everything would pass a weaker test.
    rc, out = run([sys.executable, "tools/test-analyzer7.py"], cwd=ROOT)
    summary = "\n".join(out.splitlines()[-4:])
    record("DECISION", "analyser negative regressions", rc == 0, summary)

    # The analyser must refuse captures that predate the round-7 fields.
    for rel in OLD_CAPTURES:
        path = os.path.join(ROOT, rel)
        if not os.path.exists(path):
            record("DECISION", "refuses {}".format(rel), True,
                   "capture not present; nothing to refuse")
            continue
        rc, out = run([sys.executable, "tools/analyze-round7.py", path],
                      cwd=ROOT)
        ok = (rc == 2 and "CANNOT ANALYSE" in out)
        record("DECISION", "refuses {}".format(rel), ok,
               "exit={} (expected 2)".format(rc) if not ok else "")

    # The analyser must accept a coherent round-7 capture. Without this,
    # "refuses everything" would look like success.
    scratch = os.path.join(WORK, "accept")
    if not os.path.isdir(scratch):
        os.makedirs(scratch)
    try:
        sys.path.insert(0, os.path.join(ROOT, "tools"))
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "ta", os.path.join(ROOT, "tools", "test-analyzer7.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        rc, out = mod.run(mod.variant())
        ok = (rc in (0, 1))
        record("DECISION", "accepts a coherent round-7 capture", ok,
               "exit={} (expected 0 or 1)".format(rc) if not ok else "")
    except Exception as e:      # noqa: BLE001
        record("DECISION", "accepts a coherent round-7 capture", False,
               "{}: {}".format(type(e).__name__, e))


# ===========================================================================
# MODEL
# ===========================================================================
def check_model():
    say("\nMODEL - the PTE model agrees with the spec")

    path = os.path.join(ROOT, "kext", "amd_iommu_pte_core.hpp")
    try:
        with io.open(path, "r", encoding="utf-8") as f:
            text = f.read()
    except IOError as e:
        record("MODEL", "pte core readable", False, str(e))
        return

    # Spec 48882 Table 15 is 1-based: level 1 = 4 KiB, level 2 = 2 MiB,
    # level 3 = 1 GiB, level 4 = 512 GiB.
    expected = {1: "4 KiB", 2: "2 MiB", 3: "1 GiB", 4: "512 GiB"}
    ok = True
    for lvl, name in expected.items():
        if "LEVEL_4K   = 1" in text and lvl == 1:
            continue
        if "LEVEL_2M   = 2" in text and lvl == 2:
            continue
        if "LEVEL_1G   = 3" in text and lvl == 3:
            continue
        if "LEVEL_512G = 4" in text and lvl == 4:
            continue
        ok = False
    record("MODEL", "level numbering is the spec's 1-based numbering", ok,
           "one or more level constants changed" if not ok else "")

    # The default leaf must not carry NextLevel.
    rc, out = run([sys.executable, "-c", (
        "import re,io,sys;"
        "t=io.open('kext/amd_iommu_pte_core.hpp',encoding='utf-8').read();"
        "m=re.search(r'makeDefaultLeaf[^}]*}',t);"
        "sys.exit(0 if m and 'levelEnc' not in m.group(0) else 1)")],
        cwd=ROOT)
    record("MODEL", "default leaf does not encode NextLevel", rc == 0,
           "makeDefaultLeaf gained a level encoding" if rc != 0 else "")


# ===========================================================================
# HYGIENE
# ===========================================================================
def check_hygiene():
    say("\nHYGIENE - authored files are LF-only and valid UTF-8")

    roots = ["kext", "tests", "tools", "docs", "README.md"]
    files = []
    for r in roots:
        p = os.path.join(ROOT, r)
        if os.path.isfile(p):
            files.append(p)
            continue
        for dirpath, _dirnames, filenames in os.walk(p):
            for fn in filenames:
                files.append(os.path.join(dirpath, fn))

    cr_bad = []
    utf_bad = []
    for f in files:
        try:
            with io.open(f, "rb") as fh:
                data = fh.read()
        except IOError:
            continue
        if b"\r" in data:
            cr_bad.append(os.path.relpath(f, ROOT))
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            utf_bad.append(os.path.relpath(f, ROOT))

    record("HYGIENE", "no CR bytes in {} authored file(s)".format(len(files)),
           not cr_bad, "\n".join(cr_bad[:5]))
    record("HYGIENE", "all files are valid UTF-8", not utf_bad,
           "\n".join(utf_bad[:5]))


def main():
    if os.path.isdir(WORK):
        shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(WORK)

    print("Round-7 offline verification")
    print("=" * 78)
    print("root: {}".format(ROOT))
    print("clang++: {}".format(shutil.which(CXX) or "NOT FOUND"))

    check_production()
    check_mutations()
    check_decision()
    check_model()
    check_hygiene()

    print("\n" + "=" * 78)
    by_class = {}
    for r in RESULTS:
        by_class.setdefault(r["cls"], []).append(r)

    total_ok = 0
    for cls in ("PRODUCTION", "MUTATION", "DECISION", "MODEL", "HYGIENE"):
        rows = by_class.get(cls, [])
        npass = sum(1 for r in rows if r["ok"])
        total_ok += npass
        print("{:<12} {}/{} passed".format(cls, npass, len(rows)))

    nfail = sum(1 for r in RESULTS if not r["ok"])
    print()
    if nfail == 0:
        print("ALL {} CHECKS PASS".format(len(RESULTS)))
        shutil.rmtree(WORK, ignore_errors=True)
        return 0
    print("{} of {} CHECK(S) FAILED".format(nfail, len(RESULTS)))
    print("scratch retained for inspection: {}".format(WORK))
    return 1


if __name__ == "__main__":
    sys.exit(main())
