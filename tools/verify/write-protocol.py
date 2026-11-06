#!/usr/bin/env python3
"""verify-write-protocol.py -- does the real test suite catch round 10's protocol?

WHY
---
tests/obs-write-test.cpp passes against the round-12 protocol. That is only
meaningful if the SAME test FAILS against the protocol round 10 shipped, and
against round 11's protocol too.

So this script rebuilds the real test binary three times, against three
headers:

  round 10   unconditional exchange + "ownership re-check"; plain `+=` loss
             counters; publisher copies bytes with plain loads
  round 11   bounded lock (writer side fixed); publisher still copies bytes
             with plain loads, and loss counters still plain `+=`
  round 12   the shipped header

and requires:

  round 12  : exit 0, every check passes
  round 11  : exit NON-ZERO. The defect is real but not a body-mixing one --
              it is the writer/publisher data race plus non-atomic counters.
              The test must catch it on the counters at minimum, because that
              is the assertion that runs without TSan.
  round 10  : exit NON-ZERO, and specifically on the mixed-body assertion.

A test that passed against all three would be proving nothing.

WHY THE COUNTER ASSERTION IS THE ONE THAT BITES FOR ROUND 11
------------------------------------------------------------
A data race is only *observable* under TSan or on a machine that reorders.
The non-atomic counter, by contrast, loses increments deterministically enough
to be caught by the 8x20000 concurrency test on any multicore host. So the
suite is designed so that each round's actual defect is caught by an assertion
that does not depend on luck.

Exit 0 only when all three expectations hold.
"""
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WORK = os.path.join(ROOT, 'build-work-r12', 'writeproto')
CXX = os.environ.get('CXX', 'clang++')

# ---------------------------------------------------------------------------
# Round 10's protocol, verbatim from tools/build/patch-lucy-obs.py as it stood at
# the end of round 10. The ONLY differences from round 12 are the ones under
# test: no lock around the body, an unconditional slot exchange, and plain
# counters.
# ---------------------------------------------------------------------------
ROUND10 = r'''
#ifndef RTL812xObsWrite_hpp
#define RTL812xObsWrite_hpp
#define kObsSeqOffset   16u
#define kObsHeadOffset  16u
#define kObsDropOffset  24u
#define kObsWrapOffset  20u
#define kObsLockSpinMax 4096u
#define kObsRecBytesWire 72u
#define kObsRecWords     (kObsRecBytesWire / 8u)
#define kObsSeqWord      (kObsSeqOffset / 8u)
#define kObsSeqWordLowHalf  0x00000000FFFFFFFFULL
#define kObsSeqWordHighHalf 0xFFFFFFFF00000000ULL
namespace obslog {
typedef unsigned long long Word;
static inline bool lockAcquire(volatile unsigned int *) { return true; }
static inline void lockRelease(volatile unsigned int *) {}
static inline void countLoss(unsigned int *c) { if (c) *c += 1u; }
static inline unsigned int readLoss(const unsigned int *c) { return c ? *c : 0; }
static inline unsigned int claimTicket(unsigned char *hdr) {
    return __atomic_fetch_add((unsigned int *)(hdr + kObsHeadOffset), 1u,
                              __ATOMIC_RELAXED) + 1u;
}
template <typename FillFn, typename Ctx>
static inline bool writeRecord(volatile unsigned int *,
                               unsigned char *hdr,
                               unsigned char *recBase,
                               unsigned int capacityMask,
                               FillFn fillBody, Ctx ctx,
                               unsigned int *dropped,
                               unsigned int *wrapped_unused = nullptr) {
    (void)wrapped_unused;
    const unsigned int ticket = claimTicket(hdr);
    unsigned char *rec = recBase +
        (unsigned long)(ticket & capacityMask) * 72ul;
    unsigned int *seq = (unsigned int *)(rec + kObsSeqOffset);
    const unsigned int busy = (ticket << 1) | 1u;
    const unsigned int prev = __atomic_exchange_n(seq, busy, __ATOMIC_ACQ_REL);
    if (prev != 0) {
        __atomic_fetch_add((unsigned int *)(hdr + kObsWrapOffset), 1u,
                           __ATOMIC_RELAXED);
    }
    fillBody(rec, ctx);
    if (__atomic_load_n(seq, __ATOMIC_ACQUIRE) != busy) {
        if (dropped) *dropped += 1u;
        return false;
    }
    __atomic_store_n(seq, ticket << 1, __ATOMIC_RELEASE);
    return true;
}
static inline unsigned int publishCopy(const unsigned char *recBase,
                                       unsigned int capacityMask,
                                       unsigned int capacity,
                                       unsigned int firstTicket,
                                       unsigned int n,
                                       unsigned char *dstRecs,
                                       unsigned int recBytes,
                                       unsigned int *valid,
                                       unsigned int *lost) {
    unsigned int copied = 0, holes = 0, good = 0;
    while (copied < n) {
        const unsigned int ticket = firstTicket + copied;
        const unsigned int off = ticket & capacityMask;
        unsigned int run = capacity - off;
        if (run > n - copied) run = n - copied;
        for (unsigned int k = 0; k < run; k++) {
            const unsigned char *src =
                recBase + (unsigned long)(off + k) * (unsigned long)recBytes;
            unsigned char *dst =
                dstRecs + (unsigned long)(copied + k) * (unsigned long)recBytes;
            const unsigned int seq =
                __atomic_load_n((const unsigned int *)(src + kObsSeqOffset),
                                __ATOMIC_ACQUIRE);
            if (seq == 0 || (seq & 1u) || (seq >> 1) != (ticket + k)) {
                for (unsigned int z = 0; z < recBytes; z++) dst[z] = 0;
                holes++; continue;
            }
            for (unsigned int z = 0; z < recBytes; z++) dst[z] = src[z];
            if (__atomic_load_n((const unsigned int *)(src + kObsSeqOffset),
                                __ATOMIC_ACQUIRE) != seq) {
                for (unsigned int z = 0; z < recBytes; z++) dst[z] = 0;
                holes++; continue;
            }
            good++;
        }
        copied += run;
    }
    if (valid) *valid = good;
    if (lost) *lost = holes;
    return holes;
}
}
#endif
'''

# ---------------------------------------------------------------------------
# Round 11's protocol: the writer was fixed (bounded lock), the publisher was
# not, and the counters were not.
# ---------------------------------------------------------------------------
ROUND11 = r'''
#ifndef RTL812xObsWrite_hpp
#define RTL812xObsWrite_hpp
#define kObsSeqOffset   16u
#define kObsHeadOffset  16u
#define kObsDropOffset  24u
#define kObsWrapOffset  20u
#define kObsLockSpinMax 4096u
#define kObsRecBytesWire 72u
#define kObsRecWords     (kObsRecBytesWire / 8u)
#define kObsSeqWord      (kObsSeqOffset / 8u)
#define kObsSeqWordLowHalf  0x00000000FFFFFFFFULL
#define kObsSeqWordHighHalf 0xFFFFFFFF00000000ULL
namespace obslog {
typedef unsigned long long Word;
static inline bool lockAcquire(volatile unsigned int *lock) {
    for (unsigned i = 0; i < kObsLockSpinMax; i++) {
        unsigned expected = 0;
        if (__atomic_compare_exchange_n(lock, &expected, 1u, false,
                                        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            return true;
#if defined(__i386__) || defined(__x86_64__)
        __builtin_ia32_pause();
#else
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
#endif
    }
    return false;
}
static inline void lockRelease(volatile unsigned int *lock) {
    __atomic_store_n(lock, 0u, __ATOMIC_RELEASE);
}
static inline void countLoss(unsigned int *c) { if (c) *c += 1u; }
static inline unsigned int readLoss(const unsigned int *c) { return c ? *c : 0; }
static inline unsigned int claimTicket(unsigned char *hdr) {
    return __atomic_fetch_add((unsigned int *)(hdr + kObsHeadOffset), 1u,
                              __ATOMIC_RELAXED) + 1u;
}
template <typename FillFn, typename Ctx>
static inline bool writeRecord(volatile unsigned int *lock,
                               unsigned char *hdr,
                               unsigned char *recBase,
                               unsigned int capacityMask,
                               FillFn fillBody, Ctx ctx,
                               unsigned int *dropped,
                               unsigned int *wrapped_unused = nullptr) {
    (void)wrapped_unused;
    if (!lockAcquire(lock)) { if (dropped) *dropped += 1u; return false; }
    const unsigned int ticket = claimTicket(hdr);
    unsigned char *rec = recBase +
        (unsigned long)(ticket & capacityMask) * 72ul;
    unsigned int *seq = (unsigned int *)(rec + kObsSeqOffset);
    const unsigned int busy = (ticket << 1) | 1u;
    const unsigned int prev = __atomic_exchange_n(seq, busy, __ATOMIC_ACQ_REL);
    if (prev != 0) {
        __atomic_fetch_add((unsigned int *)(hdr + kObsWrapOffset), 1u,
                           __ATOMIC_RELAXED);
    }
    fillBody(rec, ctx);
    __atomic_store_n(seq, ticket << 1, __ATOMIC_RELEASE);
    lockRelease(lock);
    return true;
}
static inline unsigned int publishCopy(const unsigned char *recBase,
                                       unsigned int capacityMask,
                                       unsigned int capacity,
                                       unsigned int firstTicket,
                                       unsigned int n,
                                       unsigned char *dstRecs,
                                       unsigned int recBytes,
                                       unsigned int *valid,
                                       unsigned int *lost) {
    unsigned int copied = 0, holes = 0, good = 0;
    while (copied < n) {
        const unsigned int ticket = firstTicket + copied;
        const unsigned int off = ticket & capacityMask;
        unsigned int run = capacity - off;
        if (run > n - copied) run = n - copied;
        for (unsigned int k = 0; k < run; k++) {
            const unsigned char *src =
                recBase + (unsigned long)(off + k) * (unsigned long)recBytes;
            unsigned char *dst =
                dstRecs + (unsigned long)(copied + k) * (unsigned long)recBytes;
            const unsigned int seq =
                __atomic_load_n((const unsigned int *)(src + kObsSeqOffset),
                                __ATOMIC_ACQUIRE);
            if (seq == 0 || (seq & 1u) || (seq >> 1) != (ticket + k)) {
                for (unsigned int z = 0; z < recBytes; z++) dst[z] = 0;
                holes++; continue;
            }
            for (unsigned int z = 0; z < recBytes; z++) dst[z] = src[z];
            if (__atomic_load_n((const unsigned int *)(src + kObsSeqOffset),
                                __ATOMIC_ACQUIRE) != seq) {
                for (unsigned int z = 0; z < recBytes; z++) dst[z] = 0;
                holes++; continue;
            }
            good++;
        }
        copied += run;
    }
    if (valid) *valid = good;
    if (lost) *lost = holes;
    return holes;
}
}
#endif
'''


def build_and_run(name, include_dir, exe, sanitize):
    flags = ['-std=c++17', '-O1', '-g', '-pthread']
    if sanitize:
        flags.append('-fsanitize=thread')
    cmd = [CXX] + flags + ['-I', include_dir, '-I', os.path.join(ROOT, 'tests'),
                           os.path.join(ROOT, 'tests', 'obs-write-test.cpp'),
                           '-o', exe]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        print('  %-10s BUILD FAILED' % name)
        print('\n'.join('    ' + l for l in p.stderr.splitlines()[:12]))
        return None, ''
    r = subprocess.run([exe], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def main():
    if os.path.isdir(WORK):
        shutil.rmtree(WORK)
    os.makedirs(WORK)

    print('=' * 78)
    print('WRITE/PUBLISH PROTOCOL: does the real suite catch the old protocols?')
    print('=' * 78)
    print('  (the SAME tests/obs-write-test.cpp is compiled against each header)')

    dirs = {}
    for name, body in (('round10', ROUND10), ('round11', ROUND11)):
        d = os.path.join(WORK, name)
        os.makedirs(d)
        open(os.path.join(d, 'RTL812xObsWrite.hpp'), 'w',
             encoding='utf-8').write(body)
        dirs[name] = d
    dirs['round12'] = os.path.join(ROOT, 'tools', 'lucy-obs')

    results = {}
    for name in ('round12', 'round11', 'round10'):
        exe = os.path.join(WORK, 'obs-write-' + name)
        rc, out = build_and_run(name, dirs[name], exe, sanitize=False)
        results[name] = (rc, out)
        if rc is None:
            print('  %-10s BUILD FAILED -- cannot judge' % name)
            return 1
        tail = [l for l in out.splitlines() if l.startswith('FAIL:')]
        print('  %-10s exit=%-3d  %d failing assertion(s)'
              % (name, rc, len(tail)))
        for l in tail[:6]:
            print('        %s' % l)

    ok = True
    rc12, out12 = results['round12']
    if rc12 != 0:
        print('\n  round 12 must PASS, but it does not.')
        ok = False

    rc11, out11 = results['round11']
    if rc11 == 0:
        print('\n  round 11 must FAIL, but the suite passes on it.')
        ok = False
    else:
        # Round 11's actual defect is the non-atomic loss counter and the
        # plain-byte publisher. The counter assertion must be among the
        # failures, because that is the one that fires without TSan.
        if 'concurrent drops are all counted' not in out11:
            print('\n  round 11 fails, but NOT on the loss counter -- the')
            print('  suite is catching it for the wrong reason.')
            ok = False

    rc10, out10 = results['round10']
    if rc10 == 0:
        print('\n  round 10 must FAIL, but the suite passes on it.')
        ok = False
    else:
        # The mixed-body defect must be caught by one of the two body-mixing
        # assertions. The deterministic one is the load-bearing case; the
        # concurrent one only fires when the scheduler happens to interleave.
        mixed = ('the deterministic interleaving produces no mixed record'
                 in out10 or
                 'NO field of the surviving record belongs to writer A' in out10)
        if not mixed:
            print('\n  round 10 fails, but NOT on a mixed-body assertion.')
            print('  That is the defect the protocol exists to prevent.')
            ok = False

    # TSan run of the shipped header: the concurrency checks must be clean.
    print('\n  ThreadSanitizer on the shipped protocol:')
    exe = os.path.join(WORK, 'obs-write-tsan')
    rc, out = build_and_run('tsan', dirs['round12'], exe, sanitize=True)
    if rc is None:
        print('    BUILD FAILED')
        ok = False
    else:
        races = [l for l in out.splitlines() if 'WARNING: ThreadSanitizer' in l]
        print('    exit=%d  data races reported: %d' % (rc, len(races)))
        for l in races[:4]:
            print('      %s' % l)
        if rc != 0 or races:
            ok = False

    print()
    print('  round 12 passes               : %s' % ('YES' if rc12 == 0 else 'NO'))
    print('  round 11 caught (loss counters): %s'
          % ('YES' if rc11 != 0 and
             'concurrent drops are all counted' in out11 else 'NO'))
    print('  round 10 caught (mixed body)   : %s'
          % ('YES' if rc10 != 0 and mixed else 'NO'))
    print()
    print('  RESULT: %s' % ('PROTOCOL FIX VERIFIED' if ok else 'FAILURES'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
