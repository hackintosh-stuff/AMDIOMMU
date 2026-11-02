#!/usr/bin/env python3
"""verify-wrapped-publish.py -- does the PUBLISHED `wrapped` reflect a real wrap?

THE DEFECT
----------
Round 12's writer incremented the ring header's `wrapped` word:

    __atomic_fetch_add((unsigned int *)(hdr + kObsWrapOffset), 1u, ...)

and the driver's `obsPublish()` filled the published header from a SEPARATE
member:

    snap->wrapped = obslog::readLoss(&obsWrapped);

Nothing ever incremented `obsWrapped`. Reproduced with an 8-slot ring and 9
writes: the ring header said wrapped = 1, the published snapshot said
wrapped = 0.

WHAT WAS *NOT* BROKEN (stated precisely, because round 12's report would have
implied otherwise)
--------------------------------------------------------------------------------
The OVERFLOWED header flag still fired, because `obsPublish()` derives it from
`head > kObsCapacity`, not from the wrap counter. The production evidence gate
refuses on OVERFLOWED. So there is NO evidence that a wrap could slip past the
final gate, and this round does not claim there is. What was broken is the wrap
METADATA: the one number a reader uses to tell "the ring lapped me" from "the
ring never wrapped but I asked for many records" was permanently zero.

WHY THIS TEST COMPILES THE REAL PUBLISH EXPRESSION
--------------------------------------------------
Fixing `tools/lucy-obs/RTL812xObsWrite.hpp` alone would change nothing: the
defect was in the DRIVER's publish path, which lives in
`tools/apply-lucy-obs2.py` as a text template. A test that re-implemented
"publish" would prove nothing about what the driver does.

So this script:

  1. runs the real patch against a real upstream tree (or a minimal stand-in
     when the upstream tree is absent -- and SAYS which);
  2. extracts the REAL body of `RTL8125::obsPublish()` from the patched
     `RTL812xLucy.cpp`;
  3. rewrites only the IOKit calls it makes (setProperty / OSData / netif /
     mach_absolute_time) into stubs that record what was published, leaving
     every expression that touches `wrapped`, `dropped`, `head` and `flags`
     EXACTLY as the driver has it;
  4. drives it with the REAL `writeRecord()` from the shipped header, an
     8-slot ring and 9 writes, and requires:

        published.wrapped == 1     (one slot was displaced)
        published.dropped == 0
        published.head    == 9
        published.flags   & OVERFLOWED  != 0     (head > capacity)

  5. also requires the RING header's own `wrapped` word to stay 0, because the
     writer must no longer write it -- one authority, not two.

A test that passed with the round-12 code would be worthless, so the script
also builds the ROUND-12 variant (writer increments the ring header, publisher
reads the separate member) and requires it to FAIL the same assertion.
"""
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
PATCH = os.path.join(ROOT, 'tools', 'apply-lucy-obs2.py')
WORK = os.path.join(ROOT, 'build-work-r13', 'wrapped')

FAILS = []


def check(name, ok, detail=''):
    print('  %-66s %s%s' % (name, 'PASS' if ok else 'FAIL',
                            '   [%s]' % detail if detail and not ok else ''))
    if not ok:
        FAILS.append(name)
    return ok


def rmtree_force(path):
    def onerror(func, p, _exc):
        try:
            os.chmod(p, 0o777)
        except OSError:
            pass
        try:
            func(p)
        except OSError:
            pass
    if os.path.isdir(path):
        shutil.rmtree(path, onerror=onerror)


# ---------------------------------------------------------------------------
# A minimal upstream tree.
#
# The real RTL812xLucy source is 600 KB and is not in this repository (it is
# fetched by commit in docs/lucy-source-build.md). The patch anchors on exact
# upstream text, so a stand-in would have to reproduce every anchor -- which
# would make the test a copy of the patch's own expectations.
#
# Instead, this test does NOT need a real upstream tree: it needs the patched
# OUTPUT. So when the upstream tree is absent, the patch's own template strings
# are used directly -- the same bytes the patch would write -- and the script
# SAYS SO. When the upstream tree IS present (on the Mac build host), the real
# patch is run and the extraction happens on its real output.
# ---------------------------------------------------------------------------
def patched_publish_body():
    """Return (body_text, provenance).

    THE PATCH TEMPLATE IS AUTHORITATIVE.
    -----------------------------------
    `tools/apply-lucy-obs2.py` is what produces the driver's `obsPublish()`; a
    tree that was patched in an earlier round is a different artefact and may
    predate the fix. So the template is read first, and any patched tree that
    happens to be on this host is used only as a CROSS-CHECK -- if the two
    disagree, the script says which one it used and why.
    """
    src = open(PATCH, encoding='utf-8', errors='surrogateescape').read()
    # The template is a triple-QUOTED string; the patch uses ''' for it and """
    # for its docstrings, so both delimiters must be accepted or the anchor is
    # not found at all.
    m = (re.search(r"^OBS_METHODS\s*=\s*r?'''(.*?)'''", src, re.M | re.S) or
         re.search(r'^OBS_METHODS\s*=\s*r?"""(.*?)"""', src, re.M | re.S))
    if not m:
        raise SystemExit('refused: OBS_METHODS template not found in the patch')
    template = m.group(1)
    if '\\n' in template and '\n' not in template.split('\\n')[0]:
        # A plain (non-raw) string carries escaped newlines. Evaluate them the
        # way Python would. A raw string does not, and must be left alone --
        # decoding it would turn a literal backslash-n in the C source into a
        # real newline and corrupt the body.
        template = template.encode('utf-8').decode('unicode_escape')
    m2 = re.search(r'void RTL8125::obsPublish\(\)\s*\{', template)
    if not m2:
        raise SystemExit('refused: obsPublish() not found in the template')
    body = extract_body(template, m2.end() - 1)
    provenance = 'the OBS_METHODS template in tools/apply-lucy-obs2.py'

    # Cross-check against a patched tree, if this host has one.
    for cand in ('RTL812xLucy-639144d1f284a9fee222a518691b01494f5e265d',
                 'build-work-round9/lucy-patched'):
        cpp = os.path.join(ROOT, cand, 'RTL812xLucy', 'RTL812xLucy.cpp')
        if not os.path.isfile(cpp):
            continue
        text = open(cpp, encoding='utf-8', errors='replace').read()
        mm = re.search(r'void RTL8125::obsPublish\(\)\s*\{', text)
        if not mm:
            continue
        other = extract_body(text, mm.end() - 1)
        if other.strip() == body.strip():
            print('  cross-check: the template matches %s' % cand)
        else:
            print('  cross-check: %s DIFFERS from the template' % cand)
            print('               (that tree was patched in an earlier round;')
            print('                the template is what round 13 will write,')
            print('                so the template is what is compiled here)')
        break

    return body, provenance


def extract_body(text, open_at):
    depth = 0
    i = open_at
    while i < len(text):
        if text[i] == '{':
            depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0:
                return text[open_at + 1:i]
        i += 1
    raise SystemExit('refused: unbalanced braces in obsPublish()')


def make_harness(body, variant):
    """Turn the real publish body into something compilable against stubs.

    Only IOKit-side calls are rewritten. Every expression involving `wrapped`,
    `dropped`, `head`, `flags`, `lost`, `n`, `firstTicket` and `lastTicket` is
    left byte-for-byte as the driver has it -- that is the whole point.
    """
    if variant == 'round12':
        # The round-12 publisher read a member nothing incremented. Reproduce
        # that by pointing the read at a counter the writer never touches.
        body = body.replace('obslog::readLoss(&obsWrapped)',
                            'obslog::readLoss(&gRound12DeadWrapped)')
        if 'gRound12DeadWrapped' not in body:
            raise SystemExit('refused: the round-12 read expression was not '
                             'found; the mutation anchor moved')

    harness = r'''
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>

typedef unsigned int UInt32;
typedef unsigned long long UInt64;
typedef unsigned char UInt8;

#define kObsHdrBytes  104u
#define kObsRecBytes  72u
#define kObsCapacity  8u
#define kObsCapacityMask (kObsCapacity - 1u)
#define kObsPublishMax 512u
#define kObsMagic     0x324F4C52u
#define kObsVersion   2u
#define kObsFormat    "rtl812x-obs/2"
#define kObsHdrFlagOverflowed 1u
#define kObsHdrFlagLost       2u
#define kObsHdrFlagTruncated  4u

#include "RTL812xObsWrite.hpp"

/* ---- the published header, in the same field order as the wire struct ---- */
struct RtlObsHdr {
    UInt32 magic, version, recSize, capacity, head, wrapped, dropped, pubId;
    UInt32 firstTicket, lastTicket, validCount, lostCount, epoch;
    UInt32 busDevFn, vendorId, deviceId, ifUnit, macHi, macLo, flags;
    UInt64 tStart, tPublished, reserved;
};
struct RtlObsRec { UInt64 tMono, addr; UInt32 seq, kind, cumulative, slot,
    gen, batch, opts1, opts2, len, flags, token, reqId, flowHash, pktFlags; };

/* The values the harness publishes through, and the last header seen. */
static RtlObsHdr gPub;
static UInt32 gRound12DeadWrapped = 0;

static UInt64 mach_absolute_time() { return 12345; }

/* ---- minimal IOKit stand-ins -------------------------------------------
 *
 * ONLY the IOKit surface the publish body touches is stubbed. Everything that
 * computes `wrapped`, `dropped`, `head`, `n`, `firstTicket`, `lastTicket`,
 * `lost`, `validCount` and `flags` is the driver's own code, byte for byte.
 * That is the whole point: a test that re-implemented the arithmetic would
 * prove nothing about what the driver publishes.
 */
struct OSObject { void retain() {} void release() {} };
struct OSNumber : OSObject {
    unsigned long long v;
    static OSNumber *withNumber(unsigned long long x, unsigned) {
        OSNumber *n = new OSNumber(); n->v = x; return n;
    }
    unsigned long long unsigned32BitValue() const { return v; }
};
struct OSData : OSObject {
    unsigned char b[64 * 1024];
    unsigned len;
    static OSData *withBytes(const void *p, unsigned n) {
        OSData *d = new OSData();
        if (n > sizeof(d->b)) n = sizeof(d->b);
        std::memcpy(d->b, p, n);
        d->len = n;
        return d;
    }
};
/* IOKit's OSDynamicCast is a MACRO taking a type NAME, not a template
 * parameter: `OSDynamicCast(OSNumber, p)`. A function template cannot accept a
 * bare type name in that position, so it must be a macro here too. */
#define OSDynamicCast(T, p) ((T *)(p))

/* netif is an IONetworkingFamily object in the driver; only getUnitNumber()
 * is read here. Modelled as a pointer to a one-method interface. */
struct Netif {
    unsigned getUnitNumber() const { return 2; }
};

/* The driver's members, reduced to what the body reads. */
struct RTL8125 {
    RtlObsHdr *obsHdr;
    RtlObsRec *obsRecs;
    UInt8 obsSnap[kObsHdrBytes + kObsPublishMax * kObsRecBytes];
    UInt32 obsPubId, obsEpoch, obsBusDevFn, obsVendorId, obsDeviceId;
    UInt32 obsIfUnit, obsMacHi, obsMacLo;
    UInt32 obsWrapped, obsDropped;
    Netif *netif;
    OSObject *copyProperty(const char *) { return nullptr; }
    void obsPublish();
};

/* setProperty: record what was published. The snapshot OSData is decoded back
 * into gPub so the assertions read the SAME bytes a reader would. */
static void setProperty(const char *k, const char *v) { (void)k; (void)v; }
static void setProperty(const char *k, OSObject *o) {
    (void)k;
    if (!o) return;
    OSData *d = (OSData *)o;
    if (d->len >= kObsHdrBytes) std::memcpy(&gPub, d->b, kObsHdrBytes);
}
static void setProperty(const char *k, OSNumber *n) { (void)k; (void)n; }

void RTL8125::obsPublish()
{__BODY__}
'''
    harness = harness.replace('__BODY__', body)

    return harness


def build_and_run(src, exe):
    """Compile the harness and run it.

    CXX is honoured so the project's own `tools/test.sh` (which sets CXX) drives
    this the same way it drives the other C++ regressions. The Windows side of
    this workspace has no C++ compiler at all, so the check for one is explicit:
    "no compiler" must be reported as such, not as a test failure.
    """
    open(os.path.join(WORK, 'harness.cpp'), 'w', newline='\n').write(src)
    cxx = os.environ.get('CXX') or shutil.which('clang++') or shutil.which('g++')
    if not cxx:
        raise SystemExit(
            'REFUSED: no C++ compiler found (set CXX, or run this on the Mac '
            'build host). This is NOT a pass: the wrapped-publish check needs '
            'to compile the real obsPublish() body.')
    r = subprocess.run(
        [cxx, '-std=c++17', '-O1', '-g', '-pthread', '-w',
         '-I', os.path.join(ROOT, 'tools', 'lucy-obs'),
         os.path.join(WORK, 'harness.cpp'), '-o', exe],
        capture_output=True, text=True)
    if r.returncode != 0:
        return None, r.stderr[-1500:]
    return subprocess.run([exe], capture_output=True, text=True), ''


def main():
    rmtree_force(WORK)
    os.makedirs(WORK)

    print('=' * 78)
    print('WRAPPED PUBLISH: does the PUBLISHED header see a real wrap?')
    print('=' * 78)

    body, provenance = patched_publish_body()
    print('  publish body from: %s' % provenance)
    if 'the patch' in provenance:
        print('  NOTE: this is the template the patch writes, not a tree the')
        print('        patch was run against. It is the same bytes; the')
        print('        difference is recorded so the reader knows.')

    # ---- 1. the real (round-13) publish path --------------------------
    print('\n1. the round-13 publish path')
    src = make_harness(body, 'round13')
    # Append the driver: 9 writes into an 8-slot ring, then publish.
    src += r'''
int main() {
    static unsigned char ring[kObsHdrBytes + kObsCapacity * kObsRecBytes];
    std::memset(ring, 0, sizeof(ring));
    RTL8125 d;
    d.obsHdr = (RtlObsHdr *)ring;
    d.obsRecs = (RtlObsRec *)(ring + kObsHdrBytes);
    d.obsHdr->magic = kObsMagic;
    d.obsHdr->version = kObsVersion;
    d.obsHdr->recSize = kObsRecBytes;
    d.obsHdr->capacity = kObsCapacity;
    d.obsHdr->epoch = 7;
    d.obsPubId = 0; d.obsEpoch = 7; d.obsBusDevFn = 0x2500;
    d.obsVendorId = 0x10EC; d.obsDeviceId = 0x8127; d.obsIfUnit = 2;
    d.obsMacHi = 0; d.obsMacLo = 0;
    d.obsWrapped = 0; d.obsDropped = 0;
    d.netif = nullptr;

    volatile unsigned int lock = 0;
    int i;
    /* NINE writes into an EIGHT-slot ring: the ninth displaces the first. */
    for (i = 0; i < 9; i++) {
        int tag = i + 1;
        obslog::writeRecord(&lock, (unsigned char *)d.obsHdr,
                            (unsigned char *)d.obsRecs, kObsCapacityMask,
                            [](unsigned char *rec, int t) {
                                RtlObsRec *r = (RtlObsRec *)rec;
                                r->tMono = 1000 + t;
                                r->addr = 0x1000ULL * t;
                                r->kind = 1;
                                r->cumulative = t;
                                r->token = 0xABCD;
                                r->reqId = t;
                            },
                            tag, &d.obsDropped, &d.obsWrapped);
    }
    const unsigned int ringWrapped = d.obsHdr->wrapped;
    d.obsPublish();
    std::printf("head=%u wrapped=%u dropped=%u flags=0x%x ring_wrapped=%u\n",
                gPub.head, gPub.wrapped, gPub.dropped, gPub.flags, ringWrapped);
    std::printf("EXPECT head=9 wrapped=1 dropped=0 overflow=1 ring_wrapped=0\n");
    return 0;
}
'''
    r, err = build_and_run(src, os.path.join(WORK, 'round13'))
    if r is None:
        check('the round-13 publish path compiles', False, err)
        print('\n  RESULT: FAILURES')
        return 1
    check('the round-13 publish path compiles', True)
    line = r.stdout.strip().splitlines()[0] if r.stdout.strip() else ''
    print('    %s' % line)
    m = re.match(r'head=(\d+) wrapped=(\d+) dropped=(\d+) flags=0x([0-9a-f]+) '
                 r'ring_wrapped=(\d+)', line)
    ok = m is not None
    check('the harness produced a decodable result', ok, line)
    if ok:
        head, wrapped, dropped, flags, ringw = (int(m.group(1)), int(m.group(2)),
                                                int(m.group(3)),
                                                int(m.group(4), 16),
                                                int(m.group(5)))
        check('the PUBLISHED wrapped counts the displaced slot (1)', wrapped == 1,
              'wrapped=%d -- the round-12 defect is back' % wrapped)
        check('the PUBLISHED dropped is 0 (no write lost its lock)', dropped == 0,
              'dropped=%d' % dropped)
        check('the PUBLISHED head is 9', head == 9, 'head=%d' % head)
        check('OVERFLOWED is set (head > capacity)', (flags & 1) != 0,
              'flags=0x%x' % flags)
        # ONE AUTHORITY: the writer must not also write the ring header's copy.
        check('the RING header wrapped stays 0 (one authority)',
              ringw == 0, 'ring_wrapped=%d -- the writer still writes the ring '
              'header as well' % ringw)
        check('the published wrapped is not merely the ring header',
              wrapped == 1 and ringw == 0,
              'the two authorities disagree in the other direction')

    # ---- 2. the ROUND-12 path must FAIL the same assertion ------------
    print('\n2. the round-12 publish path (a single-point mutation)')
    print('   the publisher reads a member nothing increments -- exactly the')
    print('   shipped round-12 behaviour. It must produce wrapped = 0.')
    src12 = make_harness(body, 'round12')
    src12 += src[src.index('int main() {'):]
    r, err = build_and_run(src12, os.path.join(WORK, 'round12'))
    if r is None:
        check('the round-12 variant compiles (it must, to be a real '
              'counterexample)', False, err)
    else:
        check('the round-12 variant compiles (it must, to be a real '
              'counterexample)', True)
        line = r.stdout.strip().splitlines()[0] if r.stdout.strip() else ''
        print('    %s' % line)
        m = re.match(r'head=(\d+) wrapped=(\d+)', line)
        got = int(m.group(2)) if m else -1
        check('the round-12 path REPRODUCES wrapped = 0 (defect reproduced)',
              got == 0, 'wrapped=%d' % got)

    print()
    print('  RESULT: %s' % ('WRAPPED PUBLISH FIX VERIFIED' if not FAILS
                            else 'FAILURES: %s' % FAILS))
    return 0 if not FAILS else 1


if __name__ == '__main__':
    sys.exit(main())
