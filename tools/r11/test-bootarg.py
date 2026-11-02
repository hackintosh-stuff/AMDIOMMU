#!/usr/bin/env python3
"""test-bootarg.py -- the amdiommu= declaration must parse the way the probe reads it.

WHY
---
Three independent pieces of code parse `amdiommu=...`:

  kext/AMDMapperProbeInternal.hpp   parsePgtBootArg()  -- gate: does the
                                    experiment run at all?
  kext/AMDMapperProbeObs.cpp        m2b2ReadDeclaredBatch() and
                                    m2b2ReadDeclaredToken() -- the declaration

If they disagree, the failure is silent: the experiment runs, the batch
predicate sees "not declared", and controlledBatchComplete is unreachable --
which is exactly what round 10 hit twice (once via a personality key, once via
a separate boot-arg that never arrived).

This script re-implements the probe's two parsers from their source text and
checks them against the strings deploy-r11.sh actually writes. It is a model,
and it says so: it does not prove the kernel delivers the argument, it proves
the parsing logic agrees.

Usage: python3 tools/r11/test-bootarg.py
"""
import re
import sys

CASES = [
    # (boot-arg value, gate open?, batch, token, why)
    ('pgt', True, 0, 0, 'the bare experiment: gate open, nothing declared'),
    ('pgt.batch4', True, 4, 0, 'batch only: token not declared'),
    ('pgt.batch4.t0xa3dbba85', True, 4, 0xA3DBBA85,
     'what deploy-r11.sh writes'),
    ('pgt.batch4.t0x00000001', True, 4, 1, 'token 1 is valid'),
    ('pgt.batch1.t0xffffffff', True, 1, 0xFFFFFFFF, 'largest token'),
    ('pgt4k.batch2.t0xdeadbeef', True, 2, 0xDEADBEEF,
     'the 4 KiB variant also carries a declaration'),
    # `parsePgtBootArg()` is `strncmp(val, "pgt", 3) == 0`, so pgthold and
    # pgtsleep DO open the gate -- they are variants of the same experiment,
    # and the round-10 comment at that function says so explicitly ("pgt4k is a
    # variant of pgt, so the gate should open too"). The variant is selected
    # later by parsePgtSleepBootArg()/parsePgtHoldBootArg(), which compare the
    # full token. Asserting the gate stays closed here was MY error in this
    # test's first version, not a defect in the probe.
    ('pgthold.batch1.t0x11111111', True, 1, 0x11111111,
     'pgthold opens the gate; it is selected as a variant afterwards'),
    ('pgtsleep', True, 0, 0,
     'pgtsleep opens the gate too, and declares nothing'),
    ('pgt.batch4.t0x0', True, 4, 0, 'token 0 is "not declared", never a token'),
    ('pgt.batch0', True, 0, 0, 'batch 0 is "not declared"'),
    ('pgt.batch', True, 0, 0, 'a bare "batch" with no digits declares nothing'),
    ('pgt.token0xabc', True, 0, 0xABC,
     'a token without a batch: order must not matter'),
    ('pgt.batch16.t0x00000002', True, 16, 2, 'a larger batch'),
    ('arm', False, 0, 0, 'a different experiment'),
    ('pgtx', True, 0, 0,
     'prefix match: "pgtx" opens the gate (strncmp(val,"pgt",3))'),
]


def gate(val):
    """parsePgtBootArg(): strncmp(val, "pgt", 3) == 0."""
    return val[:3] == 'pgt'


def parse_hex_or_dec(q):
    """m2b2ParseHexOrDec(): returns (value, rest, consumed_any)."""
    v = 0
    any_ = False
    if q[:2] in ('0x', '0X'):
        q = q[2:]
        while q and q[0] in '0123456789abcdefABCDEF':
            v = ((v << 4) | int(q[0], 16)) & 0xFFFFFFFF
            any_ = True
            q = q[1:]
    else:
        while q and q[0].isdigit():
            v = (v * 10 + int(q[0])) & 0xFFFFFFFF
            any_ = True
            q = q[1:]
    return v, q, any_


def declared_batch(val):
    """m2b2ReadDeclaredBatch(): text after the first '.', must start 'batch'."""
    dot = val.find('.')
    if dot < 0:
        return 0
    q = val[dot + 1:]
    if not q.startswith('batch'):
        return 0
    q = q[5:]
    v, _rest, any_ = parse_hex_or_dec(q)
    return v if any_ else 0


def declared_token(val):
    """m2b2ReadDeclaredToken(): scan every '.key' segment for t0x/token."""
    dot = val.find('.')
    if dot < 0:
        return 0
    q = dot
    while True:
        q = val.find('.', q)
        if q < 0:
            return 0
        q += 1
        if val[q:q + 3] == 't0x' or val[q:q + 5] == 'token':
            r = q + (5 if val[q:q + 5] == 'token' else 1)
            v, _rest, any_ = parse_hex_or_dec(val[r:])
            if any_ and v != 0:
                return v
    return 0


def main():
    print('=' * 78)
    print('BOOT-ARG DECLARATION PARSING')
    print('=' * 78)
    bad = 0
    for val, want_gate, want_batch, want_token, why in CASES:
        g = gate(val)
        b = declared_batch(val)
        t = declared_token(val)
        ok = (g == want_gate and b == want_batch and t == want_token)
        print('  %-28s gate=%-5s batch=%-2d token=0x%08x  %s'
              % (val, g, b, t, 'OK' if ok else 'MISMATCH'))
        if not ok:
            print('      wanted gate=%s batch=%d token=0x%08x'
                  % (want_gate, want_batch, want_token))
            print('      why this case exists: %s' % why)
            bad += 1
    print()
    print('  %d/%d cases behave as the probe parses them'
          % (len(CASES) - bad, len(CASES)))
    print('  RESULT: %s' % ('CONSISTENT' if bad == 0 else 'FAILURES'))
    print()
    print('  SCOPE: this models the two parsers from their source. It does not')
    print('  show that the kernel DELIVERS the argument -- that is what the')
    print('  probe publishing m2-b2-declared-raw exists to reveal, and it is')
    print('  checked from the capture, not here.')
    return 0 if bad == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
