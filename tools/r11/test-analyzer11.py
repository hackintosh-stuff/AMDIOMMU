#!/usr/bin/env python3
"""test-analyzer11.py -- negative cases for analyze-round11.py.

WHY THIS REPLACES ROUND 10'S NEGATIVE SUITE
-------------------------------------------
Round 10 counted a negative as caught when "the exit code was non-zero and the
output contained the assertion name". That is satisfied by a crash, a missing
file, or an unrelated check failing, so it cannot distinguish "the intended
guard fired" from "something went wrong somewhere".

This suite requires, for every case:

  1. the run produces a STRUCTURED result (analysis.json);
  2. the named check exists in it and has the expected state ('fail', or 'na'
     where the case is about N/A);
  3. the mutation REALLY changed the input -- the script hashes the fixture
     before and after the edit and refuses to score a case whose bytes are
     identical;
  4. every OTHER check that starts failing is declared in advance as a
     legitimate consequence of that mutation. Anything undeclared means the
     mutation had a side effect the case does not understand, which is how a
     suite avoids "something failed, call it caught".

It also keeps the positive case and a genuine control-mode N/A case, because a
suite that only ever expects failure will happily "pass" on an analyser that
rejects everything.

Usage: python3 tools/r11/test-analyzer11.py <baseline-capture>
"""
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
ANALYZER = os.path.join(ROOT, 'tools', 'analyze-round11.py')
WORK = os.path.join(ROOT, 'build-work-r11', 'cases')

HDR_BYTES = 104
REC_BYTES = 72


def sha_dir(d):
    h = hashlib.sha256()
    for name in sorted(os.listdir(d)):
        p = os.path.join(d, name)
        if os.path.isfile(p):
            h.update(name.encode())
            h.update(open(p, 'rb').read())
    return h.hexdigest()


def prop_edit(text, key, value):
    pat = re.compile(r'("%s"\s*=\s*)"[^"]*"' % re.escape(key))
    if not pat.search(text):
        return None
    return pat.sub(lambda m: m.group(1) + '"%s"' % value, text, count=1)


def hexprop_edit(text, key, value):
    pat = re.compile(r'("%s"\s*=\s*)"0x[0-9a-fA-F]+"' % re.escape(key))
    if not pat.search(text):
        return None
    return pat.sub(lambda m: m.group(1) + '"0x%x"' % value, text, count=1)


def get_hexprop(text, key):
    m = re.search(r'"%s"\s*=\s*"0x([0-9a-fA-F]+)"' % re.escape(key), text)
    return int(m.group(1), 16) if m else None


class Case:
    def __init__(self, name, target, want_state, allows=()):
        self.name = name
        self.target = target
        self.want_state = want_state
        self.allows = set(allows)


# The declarations below encode what each mutation SHOULD break. A mutation that
# breaks something not listed is reported, because that would mean the case is
# changing more of the evidence than it claims to.
CASES = [
    Case('leaf-without-IR',
         'every range has the permission its direction needs', 'fail',
         allows={'=> the business DMA ranges have complete page-table '
                 'evidence'}),

    Case('dte-root-points-elsewhere',
         'every walked chain starts at the address the DTE names', 'fail',
         allows={'=> the business DMA ranges have complete page-table evidence',
                 # Moving the DTE root makes every chain start at a table the
                 # chain does not name, so the link check fails too. That is a
                 # real consequence, not a side effect.
                 'every chain links table-to-table with correct indices'}),

    Case('non-first-request-outside-window',
         "every request's completions are inside the window", 'fail',
         allows={# Pulling the window end back excludes later requests from the
                 # window entirely, so their submits and RX records are also
                 # outside it. That is exactly the point of the case.
                 "every request's TX submits are inside the window",
                 "every request's RX records are inside the window"}),

    Case('event-log-not-running',
         'the event log was enabled', 'fail'),

    Case('event-log-overflowed',
         'the raw event window was not truncated', 'fail'),

    Case('invalidation-failed',
         'the invalidation commands all completed', 'fail'),

    Case('restore-failed',
         'the original registers were restored', 'fail'),

    Case('control-mode-as-translation',
         'the DTE is valid and switched to translation', 'na'),

    Case('archived-publication-differs',
         'the blob IS that publication', 'fail'),

    Case('epoch-not-bound',
         'the driver instance was bound before the window', 'fail',
         allows={# An unbound epoch also means the snapshot cannot be attributed
                 # to an instance. Both statements are true and both must fail.
                 'the snapshot belongs to that instance'}),

    Case('token-not-declared',
         'this round declared a run token', 'fail',
         allows={# With no declared token the join token is inferred, so it no
                 # longer equals the (zero) declaration, and the recomputed
                 # batch can no longer be reached. All consequences.
                 'the records were joined on that token',
                 'that token is the one the probe declared',
                 "the probe's claim agrees with the recomputation",
                 # With no declared token the recomputed batch is NO, so
                 # the verdict line itself flips. That is the outcome.
                 '=> controlled_batch_complete'}),

    Case('window-invalid',
         'the probe reported the window as valid', 'fail'),

    Case('segment-missing-completion',
         'every TX segment of every request completed exactly once', 'fail',
         allows={# Removing a completion from the snapshot also lowers the
                 # probe's own claim, so the agreement check must differ.
                 "the probe's claim agrees with the recomputation",
                 # And it changes the blob, so the hash triple no longer
                 # matches. That is the point of exporting the hash: a
                 # mutated snapshot cannot pass as the one the probe used.
                 'the exported blob matches the probe-published sha256',
                 'the archived file matches the probe-published sha256',
                 # Zeroing the seq makes that record a hole, so the
                 # integrity check, the coverage verdict and the batch
                 # verdict all follow. Every one of those is the correct
                 # consequence of a hole in the evidence.
                 'no record is mid-write or mis-ticketed',
                 'there are no holes in the snapshot',
                 '=> records_cover_window',
                 '=> controlled_batch_complete',
                 # The removed completion also leaves that request without
                 # a done-in-window, so the per-request timing check for it
                 # flips. Correct consequence, not a side effect.
                 "every request's completions are inside the window"}),

    Case('missing-pte-level',
         'every chain links table-to-table with correct indices', 'fail',
         allows={# Zeroing a level makes the chain unlinkable AND removes the
                 # permissions that level carried, so both fail. That is what
                 # zeroing a real PTE would do.
                 'every range has the permission its direction needs',
                 '=> the business DMA ranges have complete page-table evidence'}),
]


def run_analyzer(cap, outdir):
    r = subprocess.run([sys.executable, ANALYZER, cap, outdir],
                       capture_output=True, text=True)
    j = os.path.join(outdir, 'analysis.json')
    data = None
    if os.path.exists(j):
        data = json.load(open(j))
    return r, data


def states(data):
    return {c['name']: c['state'] for c in data['checks']}


def mutate(case, d, text):
    """Apply this case's mutation. Returns the new props.txt text, or None."""
    if case.name == 'leaf-without-IR':
        v = get_hexprop(text, 'm2-b2-bw0-pte0')
        if v is None:
            return None
        return hexprop_edit(text, 'm2-b2-bw0-pte0', v & ~(1 << 61))

    if case.name == 'dte-root-points-elsewhere':
        v = get_hexprop(text, 'm2-b2-bizwalk-dte-raw')
        if v is None:
            return None
        return hexprop_edit(text, 'm2-b2-bizwalk-dte-raw', v ^ 0x1000)

    if case.name == 'non-first-request-outside-window':
        ws = get_hexprop(text, 'm2-b2-dma-t-win-start')
        if ws is None:
            return None
        # Keep the start; pull the end back to just after it, so request 1's
        # completion may still be inside while the later ones are not.
        return hexprop_edit(text, 'm2-b2-dma-t-win-end', ws + 1)

    if case.name == 'event-log-not-running':
        return prop_edit(text, 'm2-b2-evt-log', 'no')
    if case.name == 'event-log-overflowed':
        return prop_edit(text, 'm2-b2-win-raw-truncated', 'yes')
    if case.name == 'invalidation-failed':
        return prop_edit(text, 'm2-b2-stage-inv-pages', 'no')
    if case.name == 'restore-failed':
        return prop_edit(text, 'm2-b2-regs-restored', 'no')
    if case.name == 'control-mode-as-translation':
        return prop_edit(text, 'm2-b2-mode', 'control')
    if case.name == 'archived-publication-differs':
        return hexprop_edit(text, 'm2-b2-obs-used-pub-id', 999)
    if case.name == 'epoch-not-bound':
        return hexprop_edit(text, 'm2-b2-obs-epoch-bound', 0)
    if case.name == 'token-not-declared':
        return hexprop_edit(text, 'm2-b2-obs-declared-token', 0)
    if case.name == 'window-invalid':
        return prop_edit(text, 'm2-b2-window-valid', 'no')

    if case.name == 'segment-missing-completion':
        # Remove one TX completion from the DRIVER SNAPSHOT, then keep the
        # props copy of the blob in step. This mutates the real evidence rather
        # than a summary string, which is the only way to test the segment
        # check.
        snap = os.path.join(d, 'obs-snapshot-used.bin')
        if not os.path.exists(snap):
            return None
        blob = bytearray(open(snap, 'rb').read())
        n = (len(blob) - HDR_BYTES) // REC_BYTES
        changed = False
        for i in range(n):
            off = HDR_BYTES + i * REC_BYTES
            kind = struct.unpack('<I', blob[off + 20:off + 24])[0]
            if kind == 2:                      # tx-done
                struct.pack_into('<I', blob, off + 16, 0)   # seq = 0 -> hole
                changed = True
                break
        if not changed:
            return None
        open(snap, 'wb').write(bytes(blob))
        rawp = os.path.join(d, 'props.raw.txt')
        raw = open(rawp, encoding='utf-8', errors='replace').read()
        hx = bytes(blob).hex()
        raw = re.sub(r'("m2-b2-obs-snapshot-used"\s*=\s*)<[0-9a-fA-F]*>',
                     lambda m: m.group(1) + '<' + hx + '>', raw, count=1)
        open(rawp, 'w', encoding='utf-8').write(raw)
        # props.txt itself does not hold the blob, so the only change there is
        # the probe's own claim, which must now disagree.
        return prop_edit(text, 'm2-b2-obs-controlled-batch-complete', 'yes')

    if case.name == 'missing-pte-level':
        m = re.search(r'"m2-b2-bw0-pte1"\s*=\s*"0x[0-9a-fA-F]+"', text)
        if not m:
            return None
        return text.replace(m.group(0), '"m2-b2-bw0-pte1" = "0x0"', 1)

    return None


def main():
    if len(sys.argv) < 2:
        print('usage: test-analyzer11.py <baseline-capture>')
        return 2
    base = sys.argv[1]
    if not os.path.isdir(base):
        print('no such capture: %s' % base)
        return 2

    if os.path.isdir(WORK):
        shutil.rmtree(WORK)
    os.makedirs(WORK)

    print('=' * 78)
    print('ROUND-11 ANALYSER NEGATIVE SUITE')
    print('baseline: %s' % base)
    print('=' * 78)

    bdir = os.path.join(WORK, 'baseline')
    r, data = run_analyzer(base, bdir)
    if data is None:
        print('REFUSED: the baseline produced no structured result.')
        print(r.stdout[-1500:])
        print(r.stderr[-1500:])
        return 1
    base_states = states(data)
    base_fail = [k for k, v in base_states.items() if v == 'fail']
    if base_fail:
        print('REFUSED: the baseline already fails:')
        for k in base_fail:
            print('  - ' + k)
        return 1
    print('  baseline: %d checks, 0 failed, %d N/A'
          % (len(base_states),
             sum(1 for v in base_states.values() if v == 'na')))
    print()

    ok_count = 0
    bad = []
    for c in CASES:
        d = os.path.join(WORK, c.name)
        shutil.copytree(base, d)
        props_path = os.path.join(d, 'props.txt')
        before = sha_dir(d)

        text = open(props_path, encoding='utf-8', errors='replace').read()
        new = mutate(c, d, text)
        if new is None:
            print('  %-34s REFUSED: the mutation did not apply' % c.name)
            bad.append(c.name)
            continue
        if new != text:
            open(props_path, 'w', encoding='utf-8').write(new)

        after = sha_dir(d)
        if after == before:
            print('  %-34s REFUSED: the fixture bytes are unchanged' % c.name)
            bad.append(c.name)
            continue

        odir = os.path.join(WORK, c.name + '-out')
        r, data = run_analyzer(d, odir)
        if data is None:
            print('  %-34s REFUSED: no structured result (crash or bad input)'
                  % c.name)
            print('      stderr: %s' % r.stderr.strip()[:200])
            bad.append(c.name)
            continue

        st = states(data)
        got = st.get(c.target)
        if got != c.want_state:
            print('  %-34s NOT CAUGHT: %r is %r, wanted %r'
                  % (c.name, c.target, got, c.want_state))
            bad.append(c.name)
            continue

        unexpected = [k for k, v in st.items()
                      if v == 'fail' and base_states.get(k) == 'ok'
                      and k != c.target and k not in c.allows]
        if unexpected:
            print('  %-34s CAUGHT but UNEXPLAINED side effects: %s'
                  % (c.name, unexpected[:3]))
            bad.append(c.name)
            continue

        declared = sorted(k for k in c.allows if st.get(k) == 'fail')
        print('  %-34s CAUGHT  (%s -> %s)%s'
              % (c.name, c.target, got,
                 '  [+%d declared cascade]' % len(declared) if declared else ''))
        ok_count += 1

    # ---- positive: a genuine control run must be N/A, not FAIL ----
    print()
    ctl = os.path.join(WORK, 'control-mode-genuine')
    shutil.copytree(base, ctl)
    pp = os.path.join(ctl, 'props.txt')
    t = open(pp, encoding='utf-8', errors='replace').read()
    t2 = prop_edit(t, 'm2-b2-mode', 'control')
    if t2 and t2 != t:
        open(pp, 'w', encoding='utf-8').write(t2)
        r, data = run_analyzer(ctl, os.path.join(WORK, 'control-out'))
        if data is None:
            print('  %-34s REFUSED: no structured result'
                  % 'control-mode-genuine')
            bad.append('control-mode-genuine')
        else:
            st = states(data)
            na_ok = st.get('the DTE is valid and switched to translation') == 'na'
            no_fail = not any(v == 'fail' for v in st.values())
            if na_ok and no_fail:
                print('  %-34s PASS (translation checks are N/A, nothing fails)'
                      % 'control-mode-genuine')
                ok_count += 1
            else:
                print('  %-34s FAIL: na=%s unexpected_failures=%s'
                      % ('control-mode-genuine', na_ok,
                         [k for k, v in st.items() if v == 'fail'][:3]))
                bad.append('control-mode-genuine')
    else:
        print('  %-34s REFUSED: could not set control mode'
              % 'control-mode-genuine')
        bad.append('control-mode-genuine')

    print()
    print('  %d caught / %d cases, %d problems'
          % (ok_count, len(CASES) + 1, len(bad)))
    print('  RESULT: %s' % ('ALL CASES BEHAVE CORRECTLY' if not bad
                            else 'FAILURES: %s' % bad))
    return 0 if not bad else 1


if __name__ == '__main__':
    sys.exit(main())
