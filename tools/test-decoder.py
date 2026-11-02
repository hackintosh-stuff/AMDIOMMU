#!/usr/bin/env python3
"""Self-test for tools/decode-exported-pagetable.py.

Feeds the decoder two synthetic captures built from the SAME live values the
probe exported in round 4, differing only in the leaf encoding:

  A) the shipped (wrong) leaf   0x70000003844ffe01  -> must be REJECTED
  B) the corrected leaf         0x7000000384400001  -> must be ACCEPTED

This proves the decoder distinguishes them, which the round-4 decoder did
not (it accepted both, because it had no notion of table level).

Usage:  py -3 tools/test-decoder.py
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
DECODER = os.path.join(HERE, "decode-exported-pagetable.py")

# Live values from docs/evidence/20261031-165500 (round 4).
ROOT_PA = 0x2fbc0000
L3_PA = 0x2fbc1000
L2_PA = 0x2fbd0000
FAULT_ADDR = 0x384514000
ROOT_PTE = 0x600000002fbc1601      # PM_LEVEL_PDE(3, L3_PA)
L3_PTE = 0x600000002fbd0401        # PM_LEVEL_PDE(2, L2_PA)
BAD_LEAF = 0x70000003844ffe01      # shipped: NextLevel=7 + 2 MiB size field
GOOD_LEAF = 0x7000000384400001     # corrected: NextLevel=0, default 2 MiB


def make_capture(path, leaf):
    """Emit a props.txt with a 4-level walk: root(4) -> L3(3) -> L2(2) -> leaf."""
    lines = [
        '"m2-b2-dump-root-pa" = "0x{:x}"'.format(ROOT_PA),
        '"m2-b2-dump-root-level" = "0x4"',
        '"m2-b2-dump-page-mode" = "0x4"',
        '"m2-b2-dump-pt-pages" = "0x13"',
        '"m2-b2-dump-count" = "0x1"',
        '"m2-b2-dump0-addr" = "0x{:x}"'.format(FAULT_ADDR),
        '"m2-b2-dump0-depth" = "0x3"',
        '"m2-b2-dump0-pte0-level" = "0x4"',
        '"m2-b2-dump0-pte0" = "0x{:016x}"'.format(ROOT_PTE),
        '"m2-b2-dump0-pte1-level" = "0x3"',
        '"m2-b2-dump0-pte1" = "0x{:016x}"'.format(L3_PTE),
        '"m2-b2-dump0-pte2-level" = "0x2"',
        '"m2-b2-dump0-pte2" = "0x{:016x}"'.format(leaf),
    ]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def run(path):
    p = subprocess.run([sys.executable, DECODER, path],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.returncode, p.stdout.decode("utf-8", "replace")


def main():
    fails = 0
    # Write inside the project so the file sandbox permits it; the earlier
    # tempfile.mkdtemp() landed in the DSH session temp dir, which is not
    # writable under workspace-write.
    tmp = os.path.join(HERE, "..", "build-work-decoder-test")
    tmp = os.path.abspath(tmp)
    if not os.path.isdir(tmp):
        os.makedirs(tmp)

    # ---- A: the shipped leaf must be rejected ----
    a = os.path.join(tmp, "a-bad.txt")
    make_capture(a, BAD_LEAF)
    rc, out = run(a)
    print("A. shipped leaf 0x{:016x}".format(BAD_LEAF))
    if rc == 0:
        print("   FAIL: decoder ACCEPTED the shipped (illegal) leaf")
        fails += 1
    elif "ILLEGAL ENCODING" not in out:
        print("   FAIL: rejected but did not say why")
        print(out)
        fails += 1
    else:
        print("   PASS: rejected as an illegal encoding")
        for line in out.splitlines():
            if "reason" in line or "ILLEGAL" in line:
                print("   " + line.strip())
    print()

    # ---- B: the corrected leaf must be accepted ----
    b = os.path.join(tmp, "b-good.txt")
    make_capture(b, GOOD_LEAF)
    rc, out = run(b)
    print("B. corrected leaf 0x{:016x}".format(GOOD_LEAF))
    if rc != 0:
        print("   FAIL: decoder rejected the corrected leaf (rc={})".format(rc))
        print(out)
        fails += 1
    elif "EXPORTED TABLE DECODES CORRECTLY" not in out:
        print("   FAIL: no positive conclusion")
        fails += 1
    else:
        print("   PASS: accepted as a valid identity map")
        for line in out.splitlines():
            if "page sz" in line or "VALID identity" in line:
                print("   " + line.strip())
    print()

    # ---- C: a wrong-level chain must be rejected ----
    c = os.path.join(tmp, "c-skip.txt")
    make_capture(c, GOOD_LEAF)
    # Rewrite step0 to point straight at level 2 (level skipping).
    txt = open(c, encoding="utf-8").read()
    txt = txt.replace('"m2-b2-dump0-pte0" = "0x600000002fbc1601"',
                      '"m2-b2-dump0-pte0" = "0x600000002fbd0401"')
    open(c, "w", encoding="utf-8").write(txt)
    rc, out = run(c)
    print("C. level-skipping chain (root points straight at level 2)")
    if rc == 0:
        print("   FAIL: decoder accepted a skipping chain")
        fails += 1
    else:
        print("   PASS: rejected")
    print()

    # ---- D: an absent entry must be rejected ----
    d = os.path.join(tmp, "d-absent.txt")
    make_capture(d, GOOD_LEAF)
    txt = open(d, encoding="utf-8").read()
    txt = txt.replace('"m2-b2-dump0-pte1" = "0x600000002fbd0401"',
                      '"m2-b2-dump0-pte1" = "0x0000000000000000"')
    open(d, "w", encoding="utf-8").write(txt)
    rc, out = run(d)
    print("D. absent intermediate PTE")
    if rc == 0:
        print("   FAIL: decoder accepted an absent entry")
        fails += 1
    else:
        print("   PASS: rejected")
    print()

    print("=" * 60)
    if fails:
        print("RESULT: FAIL ({} problems)".format(fails))
        return 1
    print("RESULT: ALL DECODER SELF-TESTS PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
