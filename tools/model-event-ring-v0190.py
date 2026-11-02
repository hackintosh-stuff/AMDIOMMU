#!/usr/bin/env python3
"""Offline behavioural model of the v0.19.0 event-ring consumer and command
context. This is a MODEL CHECK, not a verification of the real hardware.

WHAT IS BEING TESTED
--------------------
The C code in AMDMapperProbe.cpp cannot be run here, so the ring-consumer and
command-context logic is reimplemented in Python against the SAME rules and
driven through cases that the real hardware cannot be made to produce on
demand: ring wrap, overflow, torn entries, pointer corruption, and command
timeouts.

A pass here means "the algorithm as specified behaves correctly on these
inputs". It says NOTHING about whether the IOMMU actually produced those
inputs. That distinction is printed explicitly at the end so the output
cannot be mistaken for a hardware result.

Model rules (from Linux v6.6 iommu.c:689-702 and AMD IOMMU Spec 48882):
  * HEAD is the consumer index, advanced only by software.
  * TAIL is the producer index, written only by hardware.
  * Entries are 16 bytes; the ring is 8192 bytes = 512 slots.
  * Consumption walks [head, tail) in 16-byte steps modulo 8192.
  * A window is INVALID if: overflow seen, EVT_RUN clear, head moved,
    tail moved backwards, pointers misaligned/out of range, an entry has
    type 0 (torn/unwritten), or the byte span exceeds ring capacity.
"""
import os
import sys

RING = 8192
SLOT = 16
SLOTS = RING // SLOT
EVT_OVERFLOW = 1 << 0
EVT_RUN = 1 << 3


class Ring:
    """A model of the IOMMU event ring with separate producer/consumer roles."""

    def __init__(self):
        self.mem = bytearray(RING)
        self.head = 0
        self.tail = 0
        self.status = EVT_RUN

    # ---- hardware side ----
    def produce(self, devid, etype, flags, addr):
        if self.status & EVT_OVERFLOW:
            return  # hardware stops producing once overflowed
        slot = self.tail // SLOT
        # If the producer would overtake the consumer, the real hardware
        # sets EVT_OVERFLOW and stops. Model that exactly.
        if (self.tail + SLOT) % RING == self.head:
            self.status |= EVT_OVERFLOW
            return
        off = self.tail
        import struct
        struct.pack_into("<IIII", self.mem, off,
                         devid & 0xFFFF,
                         ((etype & 0xF) << 28) | ((flags & 0xFFF) << 16),
                         addr & 0xFFFFFFFF,
                         (addr >> 32) & 0xFFFFFFFF)
        self.tail = (self.tail + SLOT) % RING

    def produce_torn(self):
        """Write an all-zero slot and advance tail: a torn/unwritten entry."""
        off = self.tail
        self.mem[off:off + SLOT] = b"\x00" * SLOT
        self.tail = (self.tail + SLOT) % RING

    # ---- software side (mirror of m2b2SampleEvents) ----
    def sample(self, tgt_devid, produce_during=None):
        w = {
            "valid": False, "reason": "not-run",
            "headStart": 0, "tailStart": 0, "headEnd": 0, "tailEnd": 0,
            "statusStart": 0, "statusEnd": 0,
            "entries": 0, "typeCount": [0] * 16,
            "devidMismatch": 0, "raw": [],
        }
        w["headStart"] = self.head
        w["tailStart"] = self.tail
        w["statusStart"] = self.status

        if w["statusStart"] & EVT_OVERFLOW:
            w["reason"] = "overflow-at-window-start"
            return w
        if not (w["statusStart"] & EVT_RUN):
            w["reason"] = "evt-log-not-running-at-start"
            return w
        if (w["headStart"] % SLOT) or (w["tailStart"] % SLOT) \
                or w["headStart"] >= RING or w["tailStart"] >= RING:
            w["reason"] = "head-tail-out-of-range-at-start"
            return w

        # observation window
        if produce_during:
            produce_during(self)

        w["headEnd"] = self.head
        w["tailEnd"] = self.tail
        w["statusEnd"] = self.status

        if w["statusEnd"] & EVT_OVERFLOW:
            w["reason"] = "overflow-during-window"
            return w
        if not (w["statusEnd"] & EVT_RUN):
            w["reason"] = "evt-log-stopped-during-window"
            return w
        if (w["headEnd"] % SLOT) or (w["tailEnd"] % SLOT) \
                or w["headEnd"] >= RING or w["tailEnd"] >= RING:
            w["reason"] = "head-tail-out-of-range-at-end"
            return w
        if w["headEnd"] != w["headStart"]:
            w["reason"] = "head-moved-unexpectedly"
            return w

        # Consume [headStart, tailEnd) modulo the ring. Using a modular span
        # means a legitimate wrap (tail's number getting smaller) is normal.
        span = (w["tailEnd"] + RING - w["headStart"]) % RING
        if (span // SLOT) > SLOTS:
            w["reason"] = "span-exceeds-ring-capacity"
            return w

        import struct
        off = w["headStart"]
        remaining = span
        while remaining > 0:
            r = struct.unpack_from("<IIII", self.mem, off)
            t = (r[1] >> 28) & 0xF
            if t == 0:
                w["reason"] = "incomplete-entry-type-zero"
                self.head = off
                return w
            w["entries"] += 1
            if t < 16:
                w["typeCount"][t] += 1
            if (r[0] & 0xFFFF) != tgt_devid:
                w["devidMismatch"] += 1
            if len(w["raw"]) < 8:
                w["raw"].append(r)
            off = (off + SLOT) % RING
            remaining -= SLOT

        self.head = w["tailEnd"]
        w["valid"] = True
        w["reason"] = None
        return w


def case(name, expect_valid, expect_reason=None, expect_entries=None):
    return (name, expect_valid, expect_reason, expect_entries)


def main():
    results = []

    def check(name, ok, detail=""):
        results.append((name, ok, detail))
        print("  {:<52} {}".format(name, "PASS" if ok else "FAIL"))
        if not ok and detail:
            print("       " + detail)

    print("Model check: event-ring consumer (mirrors m2b2SampleEvents)")
    print("=" * 74)

    # 1. Simple: three IO_PAGE_FAULTs from the target device
    r = Ring()
    for i in range(3):
        r.produce(0x2500, 0x2, 0x20, 0x1000 * (i + 1))
    w = r.sample(0x2500)
    check("3 faults -> valid, 3 entries, type2=3",
          w["valid"] and w["entries"] == 3 and w["typeCount"][2] == 3,
          str(w))
    check("HEAD advanced to TAIL after consume",
          r.head == r.tail, "head={} tail={}".format(r.head, r.tail))

    # 2. No events at all
    r = Ring()
    w = r.sample(0x2500)
    check("no events -> valid window with 0 entries",
          w["valid"] and w["entries"] == 0, str(w["reason"]))

    # 3. Ring wrap: fill to the very end, then produce across the boundary
    r = Ring()
    produced = 0
    while r.tail != RING - SLOT:
        r.produce(0x2500, 0x2, 0x20, 0x1000)
        produced += 1
    w0 = r.sample(0x2500)
    check("consume up to end of ring",
          w0["valid"] and r.head == r.tail, str(w0["reason"]))
    # now produce across the wrap point
    for i in range(5):
        r.produce(0x2500, 0x2, 0x20, 0x2000 + i)
    w = r.sample(0x2500)
    check("5 events across the wrap boundary -> 5 entries",
          w["valid"] and w["entries"] == 5,
          "valid={} entries={} reason={}".format(
              w["valid"], w["entries"], w["reason"]))
    # After consuming, HEAD has caught up to TAIL, so the two are equal and
    # "tail < tailStart" cannot be observed from the post-consume snapshot.
    # The meaningful assertions are the two above: the window is valid and
    # every entry was recovered.
    check("HEAD caught up to TAIL after wrap consumption",
          r.head == r.tail,
          "head={} tail={}".format(r.head, r.tail))

    # 3b. A legitimate wrap must now be VALID and the entries recovered.
    # This is the case that the earlier head/tail arithmetic got wrong: it
    # started the walk at tailStart, so events produced between windows were
    # silently dropped, and it treated a wrap as corruption.
    check("wrap across the ring boundary is VALID (not corruption)",
          w["valid"], "valid={} reason={}".format(w["valid"], w["reason"]))
    check("all 5 wrapped entries recovered, none dropped",
          w["entries"] == 5, "entries={}".format(w["entries"]))

    # 4. Overflow mid-window
    r = Ring()
    r.status |= EVT_OVERFLOW
    w = r.sample(0x2500)
    check("overflow at start -> INVALID, not 0 events",
          (not w["valid"]) and w["reason"] == "overflow-at-window-start",
          str(w["reason"]))

    # 5. Overflow raised during the window
    r = Ring()

    def make_overflow(ring):
        ring.status |= EVT_OVERFLOW

    w = r.sample(0x2500, produce_during=make_overflow)
    check("overflow during window -> INVALID",
          (not w["valid"]) and w["reason"] == "overflow-during-window",
          str(w["reason"]))

    # 6. EVT_RUN cleared
    r = Ring()
    r.status = 0
    w = r.sample(0x2500)
    check("EVT_RUN clear -> INVALID",
          (not w["valid"]) and w["reason"] == "evt-log-not-running-at-start",
          str(w["reason"]))

    # 7. Torn / unwritten entry inside the produced span
    r = Ring()
    r.produce(0x2500, 0x2, 0x20, 0x1000)
    r.produce_torn()
    w = r.sample(0x2500)
    check("torn entry (type 0) -> INVALID",
          (not w["valid"]) and w["reason"] == "incomplete-entry-type-zero",
          str(w["reason"]))
    check("HEAD still advanced to the torn slot (no deadlock)",
          r.head == SLOT, "head={}".format(r.head))

    # 8. Head moved underneath us
    r = Ring()
    r.produce(0x2500, 0x2, 0x20, 0x1000)

    def move_head(ring):
        ring.head = (ring.head + SLOT) % RING

    w = r.sample(0x2500, produce_during=move_head)
    check("HEAD moved during window -> INVALID",
          (not w["valid"]) and w["reason"] == "head-moved-unexpectedly",
          str(w["reason"]))

    # 9. Misaligned tail
    r = Ring()
    r.tail = 3
    w = r.sample(0x2500)
    check("misaligned tail -> INVALID",
          (not w["valid"]) and w["reason"] == "head-tail-out-of-range-at-start",
          str(w["reason"]))

    # 10. Foreign-device events are counted separately, not silently dropped
    r = Ring()
    r.produce(0x2500, 0x2, 0x20, 0x1000)
    r.produce(0x1234, 0x2, 0x20, 0x2000)
    w = r.sample(0x2500)
    check("foreign devid counted as mismatch",
          w["valid"] and w["entries"] == 2 and w["devidMismatch"] == 1,
          str(w))

    # 11. TAIL must never be written by the consumer
    r = Ring()
    for i in range(4):
        r.produce(0x2500, 0x2, 0x20, 0x1000)
    tail_before = r.tail
    r.sample(0x2500)
    check("consumer never writes TAIL",
          r.tail == tail_before,
          "tail {} -> {}".format(tail_before, r.tail))

    # 12. Type names must match the spec exactly, not be generalised
    print()
    print("Model check: event type naming (spec-exact, not generalised)")
    print("=" * 74)
    names = {
        1: "ILLEGAL_DEV_TABLE_ENTRY",
        2: "IO_PAGE_FAULT",
        3: "DEV_TAB_HARDWARE_ERROR",
        4: "PAGE_TAB_HARDWARE_ERROR",
        5: "ILLEGAL_COMMAND_ERROR",
        6: "COMMAND_HARDWARE_ERROR",
        7: "IOTLB_INV_TIMEOUT",
        8: "INVALID_DEVICE_REQUEST",
    }
    # Round 11: the probe is eight modules plus a shared header, so a
    # single-file read would inspect only the entry point. See
    # tools/r11/probe_sources.py for why this is concatenated.
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "r11"))
    import probe_sources
    src = probe_sources.text()
    for t, n in sorted(names.items()):
        check("type {} named {}".format(t, n), n in src)
    check("type 3 NOT called a generic 'device table error'",
          "DEV_TAB_ERR" not in src or "DEV_TAB_HARDWARE_ERROR" in src)

    print()
    print("Model check: command context (mirrors M2B2CmdCtx)")
    print("=" * 74)

    def inv_pages_word1(domid):
        """data[1] for INV_IOMMU_PAGES = domid | (type 3 << 28)."""
        return domid | (3 << 28)

    check("domid 0 encodes as 0x30000000",
          inv_pages_word1(0) == 0x30000000,
          hex(inv_pages_word1(0)))
    check("domid 1 encodes as 0x30000001 (NOT 0x30000000)",
          inv_pages_word1(1) == 0x30000001,
          hex(inv_pages_word1(1)))
    check("domid 0 and 1 differ in exactly one bit",
          bin(inv_pages_word1(0) ^ inv_pages_word1(1)).count("1") == 1)
    check("low 16 bits carry the full domain id",
          (inv_pages_word1(0xFFFF) & 0xFFFF) == 0xFFFF)

    # Command failure must latch and stop further submissions
    class Ctx:
        def __init__(self):
            self.failed = False
            self.submits = 0
            self.completed = 0

        def submit(self, will_complete):
            if self.failed:
                return False
            self.submits += 1
            if not will_complete:
                self.failed = True
                return False
            self.completed += 1
            return True

    c = Ctx()
    ok1 = c.submit(True)
    ok2 = c.submit(False)
    ok3 = c.submit(True)   # must be refused
    check("timeout on 2nd command latches failed",
          ok1 and (not ok2) and c.failed)
    check("3rd submission refused after failure", not ok3)
    check("only the successful command counted as completed",
          c.completed == 1, "completed={}".format(c.completed))

    print()
    print("=" * 74)
    bad = [n for n, ok, _ in results if not ok]
    if bad:
        print("MODEL CHECK FAILED ({} case(s))".format(len(bad)))
        for n in bad:
            print("  - " + n)
        return 1

    print("ALL {} MODEL CHECKS PASS".format(len(results)))
    print()
    print("SCOPE: this validates the ALGORITHM against simulated ring states.")
    print("It does NOT show that the real IOMMU produces these states, and it")
    print("is NOT a verification of the on-hardware page table or DTE.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
