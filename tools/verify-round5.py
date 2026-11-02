#!/usr/bin/env python3
"""Round-5 offline verification driver.

Runs every offline check and reports PASS/FAIL per check with an overall
exit code. Distinguishes the three kinds of check explicitly, because
conflating them is what produced the round-3/round-4 errors:

  MODEL     rebuilds the table in Python and checks the rebuild
  PRODUCTION  compiles and runs the ACTUAL shared C core the kext uses
  DECODER   decodes real exported bytes (needs a capture with root-level)
  HYGIENE   LF-only, valid UTF-8, version consistency

Usage (from MSI_X570/amd-iommu/):
    py -3 tools/verify-round5.py
"""
import io
import os
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PY = sys.executable

results = []


def run(name, kind, cmd, expect_rc=0, cwd=None):
    p = subprocess.run(cmd, cwd=cwd or ROOT, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT)
    out = p.stdout.decode("utf-8", "replace")
    ok = (p.returncode == expect_rc)
    results.append({"name": name, "kind": kind, "ok": ok,
                    "rc": p.returncode, "expected": expect_rc, "out": out})
    return ok, out


def hygiene():
    problems = []
    checked = 0
    targets = [
        "kext/AMDMapperProbe.cpp",
        "kext/AMDMapperProbe.hpp",
        "kext/AMDMapperProbe-Info.plist",
        "kext/amd_iommu_pte_core.hpp",
        "tests/pte-core-test.cpp",
        "tools/analyze-round5.py",
        "tools/decode-exported-pagetable.py",
        "tools/verify-identity-exhaustive.py",
        "tools/extract-raw-events.py",
        "tools/test-decoder.py",
        "tools/verify-round5.py",
        "tools/add-first-fail.py",
        "tools/deploy-m2-2b2.sh",
        "README.md",
    ]
    for rel in targets:
        p = os.path.join(ROOT, rel)
        if not os.path.isfile(p):
            problems.append("missing: " + rel)
            continue
        checked += 1
        data = open(p, "rb").read()
        if b"\r" in data:
            problems.append("CR byte: " + rel)
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            problems.append("invalid UTF-8: " + rel)

    # version consistency
    cpp = open(os.path.join(ROOT, "kext/AMDMapperProbe.cpp"),
               encoding="utf-8").read()
    plist = open(os.path.join(ROOT, "kext/AMDMapperProbe-Info.plist"),
                 encoding="utf-8").read()
    dep = open(os.path.join(ROOT, "tools/deploy-m2-2b2.sh"),
               encoding="utf-8").read()
    for label, text in (("cpp", cpp), ("plist", plist), ("deploy", dep)):
        if "0.20.0" not in text:
            problems.append("{} does not mention 0.20.0".format(label))
        if "0.19.0" in text:
            problems.append("{} still mentions 0.19.0".format(label))

    # the defect must be gone from production code (comments excluded, so a
    # comment that explains the old defect is not mistaken for the defect)
    import re
    code = re.sub(r"/\*.*?\*/", "", cpp, flags=re.S)
    code = re.sub(r"//[^\n]*", "", code)
    if "M2B2_LEVEL_7" in code:
        problems.append("M2B2_LEVEL_7 still referenced in code (not comments)")
    if "m2b2PtePageSize" in code:
        problems.append("level-blind m2b2PtePageSize still present in code")

    results.append({"name": "source hygiene ({} files)".format(checked),
                    "kind": "HYGIENE", "ok": not problems, "rc": 0,
                    "expected": 0, "out": "\n".join(problems)})


def main():
    print("Round-5 offline verification")
    print("=" * 78)

    # ---- PRODUCTION: the shared C core, compiled and executed on the host ----
    print("\n[PRODUCTION] shared page-table core (the code the kext runs)")
    print("-" * 78)
    build_dir = os.path.join(ROOT, "build-work-round5")
    if not os.path.isdir(build_dir):
        os.makedirs(build_dir)
    exe = os.path.join(build_dir, "pte-core-test")
    ok, out = run("compile shared core tests", "PRODUCTION",
                  ["clang++", "-std=c++17", "-O2", "-Wall", "-Wextra",
                   "-Werror", "-o", exe, "tests/pte-core-test.cpp"])
    print("  compile: {}".format("OK" if ok else "FAILED"))
    if not ok:
        print(out)
    else:
        ok2, out2 = run("run shared core tests", "PRODUCTION", [exe])
        tail = [l for l in out2.splitlines() if l.strip()][-2:]
        print("  run    : {}".format("OK" if ok2 else "FAILED"))
        for l in tail:
            print("  " + l)

    # ---- MODEL: Python rebuild, exhaustive ----
    print("\n[MODEL] exhaustive Python rebuild of the identity table")
    print("-" * 78)
    ok, out = run("exhaustive identity model", "MODEL",
                  [PY, "tools/verify-identity-exhaustive.py"])
    for line in out.splitlines():
        if line.startswith("ALL ") or line.startswith("RESULT"):
            print("  " + line)
    if not ok:
        print(out)

    # ---- DECODER: self-test on synthetic captures ----
    print("\n[DECODER] independent decoder self-tests")
    print("-" * 78)
    ok, out = run("decoder self-tests", "DECODER",
                  [PY, "tools/test-decoder.py"])
    for line in out.splitlines():
        if line.strip().startswith(("A.", "B.", "C.", "D.", "RESULT")):
            print("  " + line.strip())

    # ---- DECODER on the real round-4 capture: must REFUSE ----
    print("\n[DECODER] round-4 capture (must be refused, not passed)")
    print("-" * 78)
    cap = "docs/evidence/20261031-165500/props.txt"
    if os.path.isfile(os.path.join(ROOT, cap)):
        ok, out = run("round-4 capture refused", "DECODER",
                      [PY, "tools/decode-exported-pagetable.py", cap],
                      expect_rc=1)
        print("  refused: {}".format("OK" if ok else "FAILED"))
        for line in out.splitlines()[:3]:
            print("  " + line)
    else:
        print("  (capture not present)")

    # ---- ANALYZER on the round-4 capture: must refuse ----
    print("\n[ANALYSER] round-4 capture (must exit 2, no conclusion)")
    print("-" * 78)
    if os.path.isfile(os.path.join(ROOT, cap)):
        ok, out = run("round-4 capture cannot be analysed", "DECODER",
                      [PY, "tools/analyze-round5.py", cap], expect_rc=2)
        print("  refused: {}".format("OK" if ok else "FAILED"))
        for line in out.splitlines()[:2]:
            print("  " + line)

    # ---- HYGIENE ----
    print("\n[HYGIENE] files and versions")
    print("-" * 78)
    hygiene()
    h = results[-1]
    print("  {}".format("OK" if h["ok"] else "PROBLEMS"))
    if h["out"]:
        for line in h["out"].splitlines():
            print("    " + line)

    # ---- summary ----
    print("\n" + "=" * 78)
    fails = [r for r in results if not r["ok"]]
    for r in results:
        print("  {:<10} {:<44} {}".format(
            r["kind"], r["name"][:44], "PASS" if r["ok"] else "FAIL"))
    print()
    if fails:
        print("RESULT: FAIL ({} of {} checks)".format(len(fails), len(results)))
        return 1
    print("RESULT: ALL {} OFFLINE CHECKS PASS".format(len(results)))
    print()
    print("SCOPE: none of the above touches the target machine. The live")
    print("re-test is a separate step and is reported separately.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
