#!/usr/bin/env python3
"""verify-reproducibility.py -- is a kext build byte-reproducible?

WHY THIS EXISTS
---------------
Round 12's build-record.sh told the reader:

    "3. rebuild and compare: the build is deterministic at -O0 with a
        fixed SDK, so the uuid and sha256 should match"

That sentence was never tested. It is FALSE, and this script is what tests it.
Two consecutive builds of the SAME sources, same compiler, same SDK, produce
DIFFERENT binaries, because three things are freshly generated on every link:

  1. LC_UUID          -- clang/ld generate a random UUID per link;
  2. embedded timestamps -- a 32-bit Unix time appears in the symbol/debug
     data, so two builds a few minutes apart differ there;
  3. the ad-hoc code signature -- it covers the two above, so it differs too.

WHAT THIS MEANS FOR IDENTITY
----------------------------
It does NOT break the round-12 identity chain. That chain compares the UUID of
THE BINARY THIS BUILD PRODUCED with the UUID the RUNNING KERNEL reports for the
loaded image. Both come from ONE build, so they match or they do not -- no
reproducibility needed.

What it breaks is the CLAIM that a rebuild can be checked by comparing hashes.
A reader who rebuilds and compares sha256 will always see a difference and may
conclude the source changed. The correct check is: rebuild, then compare the
CODE, not the container.

This script measures all of that and prints the answer, so the record can say
something true instead of something convenient.

It needs two real builds. When only one build record is available it reports
what it can and says the rest is UNTESTED rather than passing.
"""
import hashlib
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
WORK = os.path.join(ROOT, 'build-work-r13', 'repro')

FAILS = []


def check(name, ok, detail=''):
    print('  %-68s %s%s' % (name, 'PASS' if ok else 'FAIL',
                            '   [%s]' % detail if detail and not ok else ''))
    if not ok:
        FAILS.append(name)
    return ok


def note(name, detail):
    print('  %-68s NOTE  %s' % (name, detail))


def macho_uuid(path):
    d = open(path, 'rb').read()
    if len(d) < 32 or d[:4] != b'\xcf\xfa\xed\xfe':
        return None
    ncmds = struct.unpack_from('<I', d, 16)[0]
    off = 32
    for _ in range(ncmds):
        cmd, sz = struct.unpack_from('<II', d, off)
        if cmd == 0x1b and sz >= 24:
            return d[off + 8:off + 24].hex()
        off += sz
    return None


def section_bytes(path, sectname):
    """Return (offset, size) of a named section, or None.

    Used to compare __text: the part that is actually the COMPILED PROGRAM,
    as opposed to the link-time metadata around it.
    """
    d = open(path, 'rb').read()
    if len(d) < 32 or d[:4] != b'\xcf\xfa\xed\xfe':
        return None
    ncmds = struct.unpack_from('<I', d, 16)[0]
    off = 32
    for _ in range(ncmds):
        cmd, sz = struct.unpack_from('<II', d, off)
        if cmd == 0x19:                      # LC_SEGMENT_64
            nsects = struct.unpack_from('<I', d, off + 64)[0]
            soff = off + 72
            for _s in range(nsects):
                name = d[soff:soff + 16].rstrip(b'\0').decode('ascii', 'replace')
                if name == sectname:
                    size = struct.unpack_from('<Q', d, soff + 40)[0]
                    foff = struct.unpack_from('<I', d, soff + 48)[0]
                    return foff, size
                soff += 80
        off += sz
    return None


def digest_region(path, foff, size):
    d = open(path, 'rb').read()
    return hashlib.sha256(d[foff:foff + size]).hexdigest()


def digest_whole(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for c in iter(lambda: f.read(1 << 20), b''):
            h.update(c)
    return h.hexdigest()


def compare(a, b, label):
    """Compare two builds of the same source, field by field.

    THIS FUNCTION DOES NOT ASSERT A RESULT. Whether a build is reproducible is
    a MEASURED property of this toolchain, not a rule to be asserted: the two
    artefacts behave differently here, and the record must say what each one
    actually does. So every line below is a measurement, and the verdict is
    derived from the measurements.
    """
    print('\n%s' % ('-' * 78))
    print('%s' % label)
    print('-' * 78)
    print('  A: %s' % a)
    print('  B: %s' % b)
    if not (os.path.exists(a) and os.path.exists(b)):
        note('both binaries are present', 'one is missing -- UNTESTED')
        return None
    sa, sb = os.path.getsize(a), os.path.getsize(b)
    print('  size: %d vs %d' % (sa, sb))

    ua, ub = macho_uuid(a), macho_uuid(b)
    ha, hb = digest_whole(a), digest_whole(b)
    ta = section_bytes(a, '__text')
    tb = section_bytes(b, '__text')
    da = digest_region(a, *ta) if ta else None
    db = digest_region(b, *tb) if tb else None

    print('  LC_UUID A: %s' % ua)
    print('  LC_UUID B: %s' % ub)
    print('  sha256  A: %s' % ha)
    print('  sha256  B: %s' % hb)
    if ta:
        print('  __text  A: %s (%d bytes)' % (da, ta[1]))
        print('  __text  B: %s' % (db or '(not located)'))

    whole_same = (ha == hb)
    uuid_same = (ua == ub)
    text_same = (da == db) if (da and db) else None

    print()
    if whole_same:
        print('  MEASURED: this artefact IS byte-reproducible.')
        print('            A rebuild can be verified by comparing sha256.')
    else:
        print('  MEASURED: this artefact is NOT byte-reproducible.')
        if uuid_same:
            print('            The UUID matches, so the difference is elsewhere:')
            print('            an embedded timestamp or signature.')
        else:
            print('            LC_UUID differs, which alone changes the whole')
            print('            file and its ad-hoc signature.')
        if text_same:
            print('            The COMPILED CODE is identical, so a rebuild can')
            print('            be verified by comparing __text, not sha256.')
        elif text_same is False:
            print('            The COMPILED CODE ALSO DIFFERS. That is more than')
            print('            link-time metadata: investigate before trusting')
            print('            any rebuild comparison at all.')
        else:
            print('            __text could not be located, so the code was not')
            print('            compared -- UNTESTED.')
    return {'whole': whole_same, 'uuid': uuid_same, 'text': text_same}


def main():
    os.makedirs(WORK, exist_ok=True)
    print('=' * 78)
    print('REPRODUCIBILITY: can a rebuild be checked by comparing hashes?')
    print('=' * 78)

    recs = os.path.join(ROOT, 'build-records')
    found = sorted(os.listdir(recs)) if os.path.isdir(recs) else []
    pairs = []
    for r in found:
        for k in ('AMDMapperProbe', 'RTL812xLucy'):
            p = os.path.join(recs, r, k + '.kext', 'Contents', 'MacOS', k)
            if os.path.exists(p):
                pairs.append((r, k, p))
    print('\n  build records present: %d' % len(found))
    for r, k, p in pairs:
        print('    %-24s %-14s %s' % (r, k, digest_whole(p)[:16]))

    for kind in ('AMDMapperProbe', 'RTL812xLucy'):
        same_kind = [(r, p) for (r, k, p) in pairs if k == kind]
        if len(same_kind) >= 2:
            # COMPARE THE LAST TWO, NOT THE FIRST TWO.
            #
            # Build records accumulate, and different rounds build different
            # SOURCES. Comparing the oldest against the newest would compare two
            # different programs and report "the code differs" -- which says
            # nothing about reproducibility. The two most recent records are the
            # pair most likely to share a source tree, and the script says which
            # pair it used so a reader can check that assumption.
            a_rec, a = same_kind[-2]
            b_rec, b = same_kind[-1]
            print('\n  comparing the two most recent %s builds: %s vs %s'
                  % (kind, a_rec, b_rec))
            print('  (assumes they were built from the same source; if a source')
            print('   change happened between them, a __text difference is')
            print('   EXPECTED and is not a reproducibility finding)')
            compare(a, b, '%s: two builds' % kind)
        else:
            print('\n%s' % ('-' * 78))
            print('%s: only %d build(s) available -- reproducibility UNTESTED'
                  % (kind, len(same_kind)))
            print('-' * 78)

    print()
    print('  WHAT THIS MEANS')
    print('  ---------------')
    print('  The identity chain (built UUID == loaded UUID) does NOT depend on')
    print('  reproducibility: both values come from ONE build. What was false in')
    print('  round 12 was the instruction to verify a rebuild by comparing')
    print('  hashes; the measurements above say what actually works, per')
    print('  artefact. The record must repeat THAT, not a blanket claim.')
    print()
    return 0


if __name__ == '__main__':
    sys.exit(main())
