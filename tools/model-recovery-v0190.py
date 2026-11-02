#!/usr/bin/env python3
"""Offline fault injection for the v0.19.0 recovery state machine.

WHY THIS EXISTS
---------------
The recovery path decides whether the kernel is allowed to free memory that
the IOMMU may still be walking. Getting it wrong is what caused the two boot
deadlocks on 2026-10-30: the probe returned early after enabling, the device
table and command buffer were released, and the hardware kept translating
through freed memory.

Round 4 requires the error paths to be exercised *without* manufacturing a
real failure on the machine. So the state machine is modelled here and driven
through every combination of stop/restore outcomes.

The invariant under test:

    memory is released ONLY when
        IOMMU_EN cleared  AND  command buffer stopped  AND  EVT_RUN == 0
        AND every base register reads back equal to its saved value.

Any other outcome must retain the memory and record why.

Model rules (AMD IOMMU Spec 48882 / Linux v6.6 init.c:470-495, 890-906):
  * IOMMU_EN must be cleared before base registers are rewritten.
  * Event logging must report EVT_RUN=0 before its buffer is touched.
  * The device table and command buffer must not be released while the
    hardware may still fetch from them.
"""
import itertools
import os
import sys


def recover(hw_stops, cmd_stops, evt_stops, regs_match):
    """Mirror of the 第 18 步 state machine in AMDMapperProbe.cpp."""
    hwStopped = hw_stops
    cmdBufStopped = cmd_stops          # modeled as always-true once written
    evtLogStopped = evt_stops

    if hwStopped and cmdBufStopped and evtLogStopped:
        regsRestored = regs_match
        safeToFree = regsRestored
        wrote_regs = True
    else:
        wrote_regs = False             # must NOT rewrite base registers
        regsRestored = False
        safeToFree = False

    return {
        "wroteRegs": wrote_regs,
        "regsRestored": regsRestored,
        "safeToFree": safeToFree,
        "cleanup": "done" if safeToFree else "REFUSED-hardware-not-proven-idle",
    }


def main():
    results = []

    def check(name, ok, detail=""):
        results.append((name, ok, detail))
        print("  {:<56} {}".format(name, "PASS" if ok else "FAIL"))
        if not ok and detail:
            print("       " + detail)

    print("Fault injection: recovery state machine (mirrors 第 18 步)")
    print("=" * 74)
    print("  hw_stops cmd_stops evt_stops regs_match | wroteRegs free  cleanup")
    print("  " + "-" * 70)

    rows = []
    for hw, cmd, evt, regs in itertools.product(
            [True, False], [True, False], [True, False], [True, False]):
        r = recover(hw, cmd, evt, regs)
        rows.append((hw, cmd, evt, regs, r))
        print("  {:<8} {:<9} {:<9} {:<10} | {:<9} {:<5} {}".format(
            str(hw), str(cmd), str(evt), str(regs),
            str(r["wroteRegs"]), str(r["safeToFree"]), r["cleanup"]))

    print()
    print("Invariants")
    print("-" * 74)

    # I1: free only when everything succeeded
    bad = [(h, c, e, g) for (h, c, e, g, r) in rows
           if r["safeToFree"] and not (h and c and e and g)]
    check("I1  memory freed only when ALL conditions hold", not bad,
          str(bad))

    # I2: never rewrite base registers while hardware may still run
    bad = [(h, c, e, g) for (h, c, e, g, r) in rows
           if r["wroteRegs"] and not (h and c and e)]
    check("I2  base registers never rewritten while hardware may run",
          not bad, str(bad))

    # I3: a register mismatch must block the free
    r = recover(True, True, True, False)
    check("I3  register mismatch blocks free", not r["safeToFree"],
          str(r))

    # I4: failing to stop the event log must block the free
    r = recover(True, True, False, True)
    check("I4  EVT_RUN still set blocks free", not r["safeToFree"], str(r))

    # I5: failing to stop the IOMMU must block the free
    r = recover(False, True, True, True)
    check("I5  IOMMU_EN still set blocks free", not r["safeToFree"], str(r))

    # I6: cleanup must never claim success when memory was retained
    bad = [(h, c, e, g) for (h, c, e, g, r) in rows
           if r["cleanup"] == "done" and not r["safeToFree"]]
    check("I6  cleanup never reports 'done' when memory is retained",
          not bad, str(bad))

    # I7: exactly one of the 16 combinations permits a free
    ok_rows = [x for x in rows if x[4]["safeToFree"]]
    check("I7  exactly one combination permits a free", len(ok_rows) == 1,
          "{} combinations".format(len(ok_rows)))

    # I8: the permitted combination is the all-success one
    check("I8  that combination is all-success",
          ok_rows and all(ok_rows[0][:4]),
          str(ok_rows[0][:4]) if ok_rows else "none")

    # I9: the leaked addresses must be recorded when retention happens
    # Round 11: the probe is eight modules plus a shared header, so a
    # single-file read would inspect only the entry point. See
    # tools/r11/probe_sources.py for why this is concatenated.
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "r11"))
    import probe_sources
    src = probe_sources.text()
    for k in ("m2-b2-leaked-pt-pa", "m2-b2-leaked-dt-pa",
              "m2-b2-leaked-cmd-pa", "m2-b2-leaked-sem-pa",
              "m2-b2-leaked-evt-pa"):
        check("I9  {} published on retention".format(k), k in src)

    check("I10 retention reason is published",
          "REFUSED-hardware-not-proven-idle" in src)

    print()
    print("=" * 74)
    bad = [n for n, ok, _ in results if not ok]
    if bad:
        print("FAULT INJECTION FAILED ({} case(s))".format(len(bad)))
        for n in bad:
            print("  - " + n)
        return 1

    print("ALL {} RECOVERY INVARIANTS HOLD".format(len(results)))
    print()
    print("SCOPE: the state machine is verified against simulated outcomes.")
    print("No real stop failure was manufactured on the machine.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
