#!/usr/bin/env python3
"""verify-record-loaded.py -- does record-loaded.sh tell "query failed" from
"not loaded"?

THE DEFECT
----------
Round 12's script ran `kmutil showloaded` up to three times (once for the
header, once per kext), used `|| true` on the per-kext calls, and printed
`<not reported by kmutil>` for BOTH "the query failed" and "the kernel answered
and did not list this kext". Those are different facts and only one of them is
about the kext.

This script drives the REAL script against a stub `sudo`/`kmutil`/`ioreg`, in
four states:

  1. the query succeeds and lists both kexts      -> identity_source = kmutil
  2. the query succeeds but lists only one        -> kmutil-partial
  3. the query FAILS, ioreg shows the instances   -> ioreg-only, and NO
                                                     "loaded: no" line anywhere
  4. the query fails and ioreg shows nothing      -> UNKNOWN

and additionally requires:

  * the query runs EXACTLY ONCE (a counter file in the stub);
  * the raw output and the exit status are saved in the record;
  * no `loaded : no` line appears when the query failed;
  * `-a x86_64` is passed (the round-12 bug that made a live kext look absent).

It also runs the FROZEN round-12 script and requires it to get state 3 wrong,
so the check is known to be sensitive to the defect rather than merely green.
"""
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
CURRENT = os.path.join(ROOT, 'tools', 'verify', 'record-loaded.sh')
FROZEN = os.path.join(ROOT, 'tools', 'verify', 'record-loaded-frozen.sh')
WORK = os.path.join(ROOT, 'build-work-r13', 'recordloaded')

FAILS = []


def check(name, ok, detail=''):
    print('  %-68s %s%s' % (name, 'PASS' if ok else 'FAIL',
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


def write_stubs(tmp):
    bindir = os.path.join(tmp, 'bin')
    os.makedirs(bindir, exist_ok=True)

    # sudo: forward the arguments, and record that kmutil was called.
    open(os.path.join(bindir, 'sudo'), 'w').write(r'''#!/bin/sh
# `sudo -n true` is the availability probe; answer yes.
if [ "$1" = "-n" ] && [ "$2" = "true" ]; then exit 0; fi
if [ "$1" = "-n" ]; then shift; fi
case "$1" in
  kmutil)
    echo "call" >> "$STUB_STATE/kmutil_calls"
    # The round-12 bug: `-a` without an architecture. The stub refuses it the
    # way the real kmutil does, so a script that omits the arch is caught.
    case " $* " in
      *" -a x86_64 "*) ;;
      *) echo "Missing value for '-a <arch>'" >&2; exit 1 ;;
    esac
    case "$(cat "$STUB_STATE/query_mode")" in
      ok-both)
        echo "Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>"
        echo "   42    0 0xffffff8000000000 0x12000    0x12000    org.maz1.AMDMapperProbe (1.0.0) A07C2D88-8190-3B86-ACB9-834F1E70A104 <...>"
        echo "   43    0 0xffffff8000100000 0x1f000    0x1f000    com.insanelymac.RTL812xLucy (1.1.200) 35B9EBC1-DB51-3C2E-9432-F156FB91ACCB <...>"
        exit 0 ;;
      ok-one)
        echo "Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>"
        echo "   43    0 0xffffff8000100000 0x1f000    0x1f000    com.insanelymac.RTL812xLucy (1.1.200) 35B9EBC1-DB51-3C2E-9432-F156FB91ACCB <...>"
        exit 0 ;;
      fail)
        echo "kmutil: could not read the auxiliary collection" >&2
        exit 74 ;;
      empty)
        echo "Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>"
        exit 0 ;;
    esac
    exit 0 ;;
esac
exec "$@"
''')

    # ioreg: controlled by a mode file.
    open(os.path.join(bindir, 'ioreg'), 'w').write(r'''#!/bin/sh
case "$(cat "$STUB_STATE/ioreg_mode")" in
  present)
    echo '    | |   +-o RTL8125  <class RTL8125>'
    echo '    | |     "IOClass" = "RTL8125"'
    echo '    | |     "rtl812x-obs-epoch" = 14'
    echo '    +-o AMDMapperProbe  <class org_maz1_AMDMapperProbe>'
    echo '      "IOClass" = "org_maz1_AMDMapperProbe"'
    echo '      "m2-b2-verdict" = "PASS-CANDIDATE-controlled-chain"'
    exit 0 ;;
  absent) exit 0 ;;
esac
exit 0
''')

    for n in ('sudo', 'ioreg'):
        os.chmod(os.path.join(bindir, n), 0o755)
    return bindir


def run(script, rec, bindir, state, mode, ioreg_mode):
    open(os.path.join(state, 'query_mode'), 'w').write(mode)
    open(os.path.join(state, 'ioreg_mode'), 'w').write(ioreg_mode)
    try:
        os.remove(os.path.join(state, 'kmutil_calls'))
    except OSError:
        pass
    env = dict(os.environ)
    env['PATH'] = bindir + os.pathsep + env.get('PATH', '')
    env['STUB_STATE'] = state
    # `sudo` and `ioreg` are resolved through PATH; the script calls them bare.
    r = subprocess.run(['sh', script, rec], capture_output=True, text=True,
                       env=env)
    calls = 0
    p = os.path.join(state, 'kmutil_calls')
    if os.path.exists(p):
        calls = len(open(p).read().split())
    return r, calls


def record_text(rec):
    p = os.path.join(rec, 'loaded-identity.txt')
    if not os.path.exists(p):
        # A second run writes a timestamped name.
        for f in sorted(os.listdir(rec)):
            if f.startswith('loaded-identity.'):
                p = os.path.join(rec, f)
    return open(p, encoding='utf-8', errors='replace').read() if os.path.exists(p) else ''


def fresh_rec(tmp, name):
    rec = os.path.join(tmp, 'rec-' + name)
    os.makedirs(rec, exist_ok=True)
    return rec


def main():
    rmtree_force(WORK)
    os.makedirs(WORK)
    bindir = write_stubs(WORK)
    state = os.path.join(WORK, 'state')
    os.makedirs(state, exist_ok=True)

    print('=' * 78)
    print('RECORD-LOADED: "query failed" vs "not loaded"')
    print('=' * 78)

    # ------------------------------------------------------------------
    print('\n1. the query succeeds and lists BOTH kexts')
    # ------------------------------------------------------------------
    rec = fresh_rec(WORK, 'both')
    r, calls = run(CURRENT, rec, bindir, state, 'ok-both', 'present')
    t = record_text(rec)
    check('the script completes', r.returncode == 0,
          (r.stderr or '').strip()[-200:])
    check('query_status is OK', 'query_status      : OK' in t,
          [l for l in t.splitlines() if 'query_status' in l])
    check('identity_source is kmutil',
          'identity_source   : kmutil' in t,
          [l for l in t.splitlines() if 'identity_source' in l])
    check('the probe UUID is the one the kernel reported',
          'A07C2D88-8190-3B86-ACB9-834F1E70A104' in t)
    check('the driver UUID is the one the kernel reported',
          '35B9EBC1-DB51-3C2E-9432-F156FB91ACCB' in t)
    check('both are marked loaded: yes', t.count('_loaded         : yes') == 2,
          '%d' % t.count('_loaded         : yes'))
    check('the query ran EXACTLY ONCE', calls == 1,
          'kmutil was called %d times' % calls)
    raw = os.path.join(rec, 'loaded-query-raw.txt')
    check('the raw query output was saved', os.path.exists(raw))
    if os.path.exists(raw):
        rt = open(raw, encoding='utf-8', errors='replace').read()
        check('the saved raw output carries the real lines',
              'A07C2D88' in rt and 'query_rc : 0' in rt)

    # ------------------------------------------------------------------
    print('\n2. the query succeeds but lists only ONE kext')
    # ------------------------------------------------------------------
    rec = fresh_rec(WORK, 'one')
    r, calls = run(CURRENT, rec, bindir, state, 'ok-one', 'present')
    t = record_text(rec)
    check('identity_source is kmutil-partial',
          'identity_source   : kmutil-partial' in t,
          [l for l in t.splitlines() if 'identity_source' in l])
    check('the kext that WAS listed is identified',
          '35B9EBC1-DB51-3C2E-9432-F156FB91ACCB' in t)
    check('the kext that was NOT listed is a definite negative, not a failure',
          'AMDMapperProbe_loaded         : no (the query succeeded' in t)
    check('and it is still not described as a failed query',
          'query_status      : OK' in t)

    # ------------------------------------------------------------------
    print('\n3. the query FAILS while ioreg shows both instances')
    # ------------------------------------------------------------------
    #
    # This is the round-12 state that produced the false "not loaded".
    rec = fresh_rec(WORK, 'fail')
    r, calls = run(CURRENT, rec, bindir, state, 'fail', 'present')
    t = record_text(rec)
    check('the script still writes a record (it does not abort)',
          os.path.exists(os.path.join(rec, 'loaded-identity.txt')))
    check('query_status says FAILED, not "not loaded"',
          'query_status      : FAILED (kmutil exited 74)' in t,
          [l for l in t.splitlines() if 'query_status' in l])
    check('identity_source is ioreg-only',
          'identity_source   : ioreg-only' in t,
          [l for l in t.splitlines() if 'identity_source' in l])
    check('NO per-kext "loaded: no" line was written',
          '_loaded         : no' not in t,
          'the script reported absence because ITS OWN query failed')
    check('the record says a failed query is not "not loaded"',
          'A FAILED QUERY IS NOT' in t)
    check('the driver instance is still reported from ioreg',
          'driver_instance : PRESENT' in t)

    # ------------------------------------------------------------------
    print('\n4. the query fails and ioreg shows nothing')
    # ------------------------------------------------------------------
    rec = fresh_rec(WORK, 'unknown')
    r, calls = run(CURRENT, rec, bindir, state, 'fail', 'absent')
    t = record_text(rec)
    check('identity_source is UNKNOWN',
          'identity_source   : UNKNOWN' in t,
          [l for l in t.splitlines() if 'identity_source' in l])
    check('no per-kext "loaded: no" line was written',
          '_loaded         : no' not in t)

    # ------------------------------------------------------------------
    print('\n5. the query omits -a x86_64 (the round-12 bug)')
    # ------------------------------------------------------------------
    #
    # The stub refuses `-a` without an architecture exactly as the real kmutil
    # does. A script that forgets the arch therefore sees a failing query --
    # which is what happened in round 12, and is why two running kexts were
    # reported as not loaded.
    rec = fresh_rec(WORK, 'noarch')
    open(os.path.join(bindir, 'sudo'), 'a').close()   # keep mtime sane
    # Point the stub at a mode that only answers when the arch is present.
    r, calls = run(CURRENT, rec, bindir, state, 'ok-both', 'present')
    t = record_text(rec)
    check('the arch argument is present in the successful path',
          'query_status      : OK' in t,
          'the script did not pass -a x86_64')

    # ------------------------------------------------------------------
    print('\n6. the FROZEN round-12 script gets state 3 wrong')
    # ------------------------------------------------------------------
    #
    # A check that passes on both the old and the new script would not be
    # sensitive to the defect. The frozen round-12 text is run against the same
    # stubs.
    #
    # WHAT IT ACTUALLY DOES, discovered by running it (this is stronger than
    # what the round-13 task described):
    #
    #   `set -eu` + `SL_OUT=$(sudo kmutil showloaded ... 2>&1)` means the
    #   assignment CARRIES the command's exit status, and `set -e` aborts on it.
    #   So the round-12 script does not merely mislabel the kexts -- it DIES
    #   inside the `{ ... } > "$OUT"` block, leaving loaded-identity.txt
    #   TRUNCATED at the "## kmutil showloaded" heading, with no query_status,
    #   no UUIDs and no ioreg section at all. The `SL_RC=$?` line after it is
    #   never reached, so the elaborate "FAILED is not 'not loaded'" prose it
    #   carries is dead code.
    #
    # That is the R1 defect, and it is worse than a false negative: the record
    # looks like a record and is a fragment.
    if not os.path.exists(FROZEN):
        check('the round-12 script is available to compare against', False,
              'missing %s' % FROZEN)
    else:
        rec = fresh_rec(WORK, 'frozen')
        r, calls = run(FROZEN, rec, bindir, state, 'fail', 'present')
        t = record_text(rec)
        check('the round-12 script leaves a TRUNCATED record',
              'query_status' not in t and 'driver_instance' not in t,
              'the frozen script produced a complete record, so the case is '
              'not testing what it claims')
        check('  and it wrote no UUID and no ioreg section at all',
              'A07C2D88' not in t and 'RTL8125' not in t)
        check('  because `set -e` aborted it inside the record block (R1)',
              not t.rstrip().endswith('substitute for it.'),
              'the record looks complete')
        # And it never reached the per-kext loop, which is where round 12 would
        # have printed `<not reported by kmutil>`.
        check('  so the per-kext loop never ran at all',
              calls == 1, 'calls=%d' % calls)
        # The current script, by contrast, survives the same failure.
        rec2 = fresh_rec(WORK, 'frozen-cmp')
        r2, _ = run(CURRENT, rec2, bindir, state, 'fail', 'present')
        t2 = record_text(rec2)
        check('the round-13 script survives the same failure and records it',
              'query_status      : FAILED' in t2 and
              'driver_instance : PRESENT' in t2)

    print()
    print('  RESULT: %s' % ('QUERY FAILURE DISTINGUISHED FROM ABSENCE'
                            if not FAILS else 'FAILURES: %s' % FAILS))
    return 0 if not FAILS else 1


if __name__ == '__main__':
    sys.exit(main())
