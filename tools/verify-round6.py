#!/usr/bin/env python3
"""Round-6 offline verification driver.

WHAT IT RUNS
------------
Every check below executes PRODUCTION code or the PRODUCTION decision
logic. None of them is a restatement of the thing being checked.

  PRODUCTION   compile the shared PTE core tests       (kext header)
  PRODUCTION   run the shared PTE core tests
  PRODUCTION   compile the DMA-observation core tests  (kext header)
  PRODUCTION   run the DMA-observation core tests
  PRODUCTION   mutation: reintroduce the round-5 fault-inversion
  PRODUCTION   mutation: reintroduce the round-4 leaf encoding
  DECISION     run the analyser's own negative regressions
  DECISION     analyser refuses the round-5 capture (schema drift)
  DECISION     analyser refuses the round-4 capture
  MODEL        exhaustive identity model
  DECODER      decoder self-tests
  HYGIENE      LF-only / no CR on every touched file

WHAT IT DOES NOT DO
-------------------
It does not touch hardware, deploy anything, or reboot. The live re-test is a
separate, explicitly recorded step.

Exit code: 0 only if every check passes.

Usage:
    py -3 tools/verify-round6.py
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
WORK = os.path.join(ROOT, "build-work-round6")

CC = os.environ.get("CXX", "clang++")

results = []


def record(kind, name, ok, detail=""):
    results.append({"kind": kind, "name": name, "ok": bool(ok),
                    "detail": detail})
    print("%-11s %-52s %s" % (kind, name, "PASS" if ok else "FAIL"))
    if detail and not ok:
        for line in detail.strip().splitlines()[-20:]:
            print("            " + line)


def run(cmd, cwd=None, timeout=300):
    try:
        p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=timeout)
        return p.returncode, p.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError) as e:
        return 127, str(e)


def need_build_dir():
    if not os.path.isdir(WORK):
        os.makedirs(WORK)


def compile_and_run(kind, label, src, extra_src=None, expect_zero=True):
    need_build_dir()
    exe = os.path.join(WORK, label)
    if os.name == "nt":
        exe += ".exe"
    cmd = [CC, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
           "-o", exe, src]
    rc, out = run(cmd, cwd=ROOT)
    if rc != 0:
        record(kind, "compile %s" % label, False, out)
        return False, ""
    record(kind, "compile %s" % label, True)
    rc, out = run([exe], cwd=ROOT)
    ok = (rc == 0) if expect_zero else True
    record(kind, "run %s" % label, ok, out)
    return ok, out


def test_mutation(label, src, mutate_fn, expect_fail=True):
    """Copy the source tree, apply a mutation, rebuild, require failure."""
    import shutil
    import tempfile
    tmp = tempfile.mkdtemp(prefix="mut-", dir=WORK)
    try:
        # Copy kext headers and tests so relative includes still resolve.
        for d in ("kext", "tests"):
            s = os.path.join(ROOT, d)
            if os.path.isdir(s):
                shutil.copytree(s, os.path.join(tmp, d))
        target = os.path.join(tmp, src)
        with open(target, "r", encoding="utf-8") as f:
            text = f.read()
        mutated = mutate_fn(text)
        if mutated == text:
            record("PRODUCTION", "mutation %s" % label, False,
                   "the mutation did not change the source")
            return
        with open(target, "w", encoding="utf-8", newline="\n") as f:
            f.write(mutated)
        exe = os.path.join(tmp, "mut")
        if os.name == "nt":
            exe += ".exe"
        test_src = os.path.join(tmp, "tests", MUTATION_TESTS[src])
        rc, out = run([CC, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
                       "-o", exe, test_src], cwd=tmp)
        if rc != 0:
            record("PRODUCTION", "mutation %s (compile)" % label, False, out)
            return
        rc, out = run([exe], cwd=tmp)
        caught = (rc != 0)
        if expect_fail:
            record("PRODUCTION", "mutation %s caught by tests" % label,
                   caught, out if not caught else
                   out.strip().splitlines()[-1] if out.strip() else "")
        else:
            record("PRODUCTION", "mutation %s (expected pass)" % label,
                   not caught, out)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


MUTATION_TESTS = {
    "kext/amd_iommu_dma_observe.hpp": "dma-observe-test.cpp",
    "kext/amd_iommu_pte_core.hpp": "pte-core-test.cpp",
}


def mutate_fault_inversion(text):
    """Reintroduce round 5's 'above 16 GiB, therefore MMIO' inversion.

    The mutation moves the map-limit test ahead of set membership, which is
    exactly what round 5 did: it decided the address was MMIO from the size
    of RAM, without ever asking whether the device owned it.
    """
    old = "    if (set.containsLive(addr, &f.purpose)) {"
    new = (
        "    if (!f.inMappedRange) {\n"
        "        f.own = OWN_OUTSIDE_ENVELOPE;\n"
        "        f.reason = \"MUTATED: above the limit, therefore MMIO\";\n"
        "        return f;\n"
        "    }\n"
        "    if (set.containsLive(addr, &f.purpose)) {"
    )
    if old not in text:
        return text
    return text.replace(old, new, 1)


def mutate_leaf_encoding(text):
    """Reintroduce round 4's NextLevel=7 spelling of a 2 MiB leaf."""
    old = """inline u64 makeDefaultLeaf(unsigned level, u64 pa, u64 perms) {
    (void)level;   // the size is implied by the level; the encoding is identical
    return (pa & PM_ADDR_MASK) | PTE_PR | PTE_FC |
           (perms & (PTE_IR | PTE_IW));
}"""
    new = """inline u64 makeDefaultLeaf(unsigned level, u64 pa, u64 perms) {
    (void)level;
    // MUTATED: round-4 spelling -- NextLevel=7 with the size bits set.
    return ((pa | 0x1FFFFFULL) & ~0x100000ULL & PM_ADDR_MASK) |
           levelEnc(NEXT_LEVEL_LARGE) | PTE_PR | PTE_FC |
           (perms & (PTE_IR | PTE_IW));
}"""
    return text.replace(old, new, 1)


def check_hygiene():
    bad = []
    count = 0
    for folder in ("kext", "tools", "tests", "docs"):
        base = os.path.join(ROOT, folder)
        if not os.path.isdir(base):
            continue
        for dirpath, _dirs, files in os.walk(base):
            for fn in files:
                if not fn.endswith((".hpp", ".h", ".cpp", ".py", ".sh",
                                    ".md", ".plist")):
                    continue
                path = os.path.join(dirpath, fn)
                count += 1
                with open(path, "rb") as f:
                    if b"\r" in f.read():
                        bad.append(os.path.relpath(path, ROOT))
    record("HYGIENE", "LF-only (%d files)" % count, not bad,
           "\n".join(bad))
    # UTF-8 validity
    badu = []
    for folder in ("kext", "tools", "tests", "docs"):
        base = os.path.join(ROOT, folder)
        if not os.path.isdir(base):
            continue
        for dirpath, _dirs, files in os.walk(base):
            for fn in files:
                if not fn.endswith((".hpp", ".h", ".cpp", ".py", ".sh",
                                    ".md", ".plist")):
                    continue
                path = os.path.join(dirpath, fn)
                try:
                    with open(path, "rb") as f:
                        f.read().decode("utf-8")
                except UnicodeDecodeError as e:
                    badu.append("%s: %s" % (os.path.relpath(path, ROOT), e))
    record("HYGIENE", "valid UTF-8", not badu, "\n".join(badu))


def check_analyser_refusals():
    # Round-5 capture lacks the round-6 fields entirely.
    r5 = os.path.join(ROOT, "docs", "evidence", "20261031-180500",
                      "props.txt")
    if os.path.isfile(r5):
        rc, out = run([sys.executable,
                       os.path.join(HERE, "analyze-round6.py"), r5])
        record("DECISION", "analyser refuses the round-5 capture", rc == 2,
               "rc=%d\n%s" % (rc, out[-800:]))
    else:
        record("DECISION", "analyser refuses the round-5 capture", False,
               "capture not present")

    # Round-4 capture has neither wall bounds nor levels.
    for stamp in ("20261031-165500", "20261031-165200"):
        r4 = os.path.join(ROOT, "docs", "evidence", stamp, "props.txt")
        if os.path.isfile(r4):
            rc, out = run([sys.executable,
                           os.path.join(HERE, "analyze-round6.py"), r4])
            record("DECISION", "analyser refuses %s" % stamp, rc == 2,
                   "rc=%d" % rc)
            break


def main():
    print("Round-6 offline verification")
    print("=" * 78)
    print("root  : %s" % ROOT)
    print("work  : %s" % WORK)
    print("compiler: %s" % CC)
    print()

    need_build_dir()

    # ---- production code: PTE core ----
    compile_and_run("PRODUCTION", "pte-core-test",
                    os.path.join(ROOT, "tests", "pte-core-test.cpp"))

    # ---- production code: DMA observation core ----
    compile_and_run("PRODUCTION", "dma-observe-test",
                    os.path.join(ROOT, "tests", "dma-observe-test.cpp"))

    # ---- mutation tests: the tests must be able to fail ----
    test_mutation("fault-inversion", "kext/amd_iommu_dma_observe.hpp",
                  mutate_fault_inversion)
    test_mutation("leaf-encoding", "kext/amd_iommu_pte_core.hpp",
                  mutate_leaf_encoding)

    # ---- decision logic: the analyser's own negative regressions ----
    rc, out = run([sys.executable,
                   os.path.join(HERE, "test-analyzer.py")])
    record("DECISION", "analyser negative regressions", rc == 0, out)

    # ---- decision logic: real old captures must be refused ----
    check_analyser_refusals()

    # ---- model ----
    p = os.path.join(HERE, "verify-identity-exhaustive.py")
    if os.path.isfile(p):
        rc, out = run([sys.executable, p])
        record("MODEL", "exhaustive identity model", rc == 0, out)

    # ---- decoder self-tests ----
    p = os.path.join(HERE, "test-decoder.py")
    if os.path.isfile(p):
        rc, out = run([sys.executable, p])
        record("DECODER", "decoder self-tests", rc == 0, out)

    # ---- hygiene ----
    check_hygiene()

    print()
    npass = sum(1 for r in results if r["ok"])
    nfail = len(results) - npass
    print("=" * 78)
    print("%d passed, %d failed" % (npass, nfail))
    if nfail == 0:
        print("RESULT: ALL %d OFFLINE CHECKS PASS" % len(results))
        return 0
    print("RESULT: FAILURES")
    for r in results:
        if not r["ok"]:
            print("  %s / %s" % (r["kind"], r["name"]))
    return 1


if __name__ == "__main__":
    sys.exit(main())
