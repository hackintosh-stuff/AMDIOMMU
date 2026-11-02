#!/usr/bin/env python3
"""Focused test for the ACTUAL probeLayout() text in the probe header.

Why this exists
---------------
Round 19 decided whether a physical layout could use IODMACommand's LINEAR
contract (mapLength == length) from the first run and from page alignment of the
following runs. That is not the framework's rule: IODMACommand answers a linear
mapping with `mapAddress + logicalOffset`, so a later run is only linear when its
position in the window (`slot + align`) equals `firstOffset + bytesSoFar`.

Counterexample this test pins down (the one that motivated round 20):

    run 0: PA 0x100100, 4096 bytes -> occupies window slots 0 and 1 (0x2000)
    run 1: PA 0x200000,   64 bytes -> the mapper places it at slot 0x2000
    linear answer  : mapAddress + 0x1000 = base + 0x1100   (WRONG, hole)
    fMapSegments   : base + 0x2000                         (actual)

The helper is EXTRACTED from kext/AMDMapperProbeInternal.hpp and compiled as-is;
only IOMemoryDescriptor is a stub, and it answers physical runs exactly the way
the header's comment describes (one scripted run at a time, in order).

Usage: python3 tools/r20/test-layout.py [--emit out.cpp]
"""
import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / 'kext' / 'AMDMapperProbeInternal.hpp'

PREFIX = r'''
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cassert>
using UInt32 = uint32_t;
using UInt64 = uint64_t;
typedef uint64_t addr64_t;
typedef uint32_t IOByteCount;
enum { kIOMemoryMapperNone = 0 };

struct IOMemoryDescriptor {
    struct Run { UInt64 pa; UInt32 len; };
    Run run[16];
    int n = 0;
    addr64_t getPhysicalSegment(IOByteCount off, IOByteCount *len, int) const {
        UInt64 at = 0;
        for (int i = 0; i < n; i++) {
            if (off < at + run[i].len) {
                if (len) *len = run[i].len - (UInt32)(off - at);
                return run[i].pa + (off - at);
            }
            at += run[i].len;
        }
        if (len) *len = 0;
        return 0;
    }
};
'''


def extract():
    text = HEADER.read_text(encoding='utf-8')
    start = text.index('struct LayoutRun {')
    fn = text.index('static inline ProbeLayout probeLayout(')
    end = text.index('\n}\n', fn) + 3
    body = text[start:end]
    # Guard: the test must compile the check it claims to test, not an older
    # body that only inspected the first run.
    if 'R.slot + (uint64_t)align != (uint64_t)L.firstOffset + consumed' not in body:
        raise SystemExit('probeLayout body does not contain the per-run linear check')
    return body


CASES = r'''
static ProbeLayout layout(IOMemoryDescriptor &md, UInt64 length) {
    return probeLayout(&md, 0, length, 8);
}

int main() {
    /* (1) THE counterexample: a page-filled first run pads the window, so the
     * second run lands at slot 0x2000, not at firstOffset + 0x1000. */
    {
        IOMemoryDescriptor md;
        md.run[0] = {0x100100, 4096};
        md.run[1] = {0x200000, 64};
        md.n = 2;
        ProbeLayout L = layout(md, 4160);
        assert(!L.error && L.runs == 2);
        assert(L.firstOffset == 0x100);
        assert(L.discontig);                      /* was false before round 20 */
        assert(L.run[0].slot == 0 && L.run[1].slot == 0x2000);
        assert(L.run[1].slot + L.run[1].align == 0x2000);
        /* the length IODMACommand must be given to build fMapSegments */
        assert((UInt64)L.pages * 4096 - L.firstOffset == 0x2F00);
        assert(L.totalBytes == 4160);
    }
    /* (2) one physically contiguous run keeps the linear contract */
    {
        IOMemoryDescriptor md;
        md.run[0] = {0x35e41100, 74};
        md.n = 1;
        ProbeLayout L = layout(md, 74);
        assert(!L.error && !L.discontig && L.runs == 1);
        assert(L.firstOffset == 0x100 && L.pages == 1);
    }
    /* (3) two page-aligned runs that really are contiguous stay linear */
    {
        IOMemoryDescriptor md;
        md.run[0] = {0x200000, 4096};
        md.run[1] = {0x201000, 4096};
        md.n = 2;
        ProbeLayout L = layout(md, 8192);
        assert(!L.discontig && L.pages == 2);
        assert(L.run[1].slot == 0x1000);
    }
    /* (4) first run ends exactly at a page boundary: the next run's slot is the
     * linear position, so this is linear even though the first run is offset. */
    {
        IOMemoryDescriptor md;
        md.run[0] = {0x100100, 0xF00};
        md.run[1] = {0x101000, 0x40};
        md.n = 2;
        ProbeLayout L = layout(md, 0xF40);
        assert(!L.discontig && L.pages == 2);
        assert(L.run[1].slot == 0x1000);
    }
    /* (5) internal padding WITHIN the window: run 0 spans two pages although it
     * only uses 0x100 of the second one; run 1 is physically adjacent
     * (0x101100) yet its window position is 0x2100, not 0x1100. */
    {
        IOMemoryDescriptor md;
        md.run[0] = {0x100100, 0x1000};
        md.run[1] = {0x101100, 0x40};
        md.n = 2;
        ProbeLayout L = layout(md, 0x1040);
        assert(L.discontig);
        assert(L.run[1].slot == 0x2000 && L.run[1].align == 0x100);
        assert(L.run[1].slot + L.run[1].align == 0x2100);
        assert((UInt64)L.pages * 4096 - L.firstOffset == 0x2F00);
    }
    /* (6) capacity: a ninth run is refused, never silently dropped */
    {
        IOMemoryDescriptor md;
        for (int i = 0; i < 9; i++) md.run[i] = {0x300000ULL + (UInt64)i * 0x1000, 64};
        md.n = 9;
        ProbeLayout L = layout(md, 9 * 64);
        assert(L.error);
    }
    (void)layout;
    std::printf("probeLayout: 6 cases passed (per-run linear contract)\n");
    return 0;
}
'''


def test_r25():
    """Pure-Python bounded-history parsing regressions; no hardware claims."""
    import importlib.util
    import struct
    import unittest
    spec = importlib.util.spec_from_file_location('r25check', Path(__file__).with_name('check-r25.py'))
    C = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(C)

    class HistoryTests(unittest.TestCase):
        def test_domain_tail(self):
            raw = bytearray(C.TAIL + 72)
            struct.pack_into('<4I', raw, 0, 3, len(raw), 32, 0)
            struct.pack_into('<16IQ', raw, C.TAIL, 512, 480, 512, 512, 8192, 4096,
                             4096, 2, 5, 0, 15, 4, 128, 128, 128, 128, 4096)
            h, rows = C.decode_domain(raw)
            self.assertEqual(h['commandWraps'], 2)
            self.assertEqual(h['completionSequence'], 4096)
            self.assertEqual(len(rows), 32)
            with self.assertRaises(C.A.Refused):
                C.decode_domain(raw[:-1])
            struct.pack_into('<I', raw, 0, 2)
            with self.assertRaises(C.A.Refused):
                C.decode_domain(raw)

        def test_ring_absolute_sequence(self):
            rows = list(range(32))
            h = {'historyTotal': 512, 'historyStart': 480, 'count': 32}
            self.assertEqual(C.retained(h, rows, 'historyTotal'), rows)
            h['historyStart'] = 479
            with self.assertRaises(C.A.Refused):
                C.retained(h, rows, 'historyTotal')

        def test_std_v4_history(self):
            raw = bytearray(72 + 32 * 304)
            struct.pack_into('<16IQ', raw, 0, C.A.STD_MAGIC, 4, len(raw), 32,
                             0, 1, 512, 0, 0, 512, 0, 4, 0, 512, 480, 480, 1)
            for i in range(32):
                struct.pack_into('<2I', raw, 72 + i * 304, 4, 304)
            h, rows = C.decode_std(raw)
            self.assertEqual(h['highReqAccepts'], 480)
            self.assertEqual(h['historyStart'], 480)
            self.assertEqual(len(rows), 32)
            self.assertEqual(C.A.STD_VERSION, 3)  # legacy module was not mutated

        def test_missing_evidence_fails(self):
            with tempfile.TemporaryDirectory() as tmp:
                report = C.check(Path(tmp))
            self.assertFalse(report['ok'])
            self.assertEqual(report['checks'][0]['state'], 'FAIL')
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(HistoryTests)
    return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--emit')
    ap.add_argument('--r25', action='store_true', help='test bounded-history ABI parsing without a C++ compiler')
    a = ap.parse_args()
    if a.r25:
        return test_r25()
    code = PREFIX + extract() + CASES
    if a.emit:
        Path(a.emit).write_text(code)
        return 0
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / 'layout.cpp'
        src.write_text(code)
        exe = Path(tmp) / 'layout'
        subprocess.run(['clang++', '-std=c++17', '-fsanitize=address,undefined',
                        str(src), '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
