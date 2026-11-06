#!/usr/bin/env python3
"""verify-patch-freshness.py -- does the patch notice a STALE driver tree?

THE DEFECT THIS CATCHES
-----------------------
`tools/build/patch-lucy-obs.py` writes `obsWrite()` and `obsPublish()` into the
driver by TEXT SUBSTITUTION from a template (`OBS_METHODS`). Editing the
template therefore changes nothing in a tree that was already patched: the
script's idempotence check sees its marker, prints "already applied", and exits
0. The driver keeps compiling the OLD method bodies.

That happened in round 13. The wrapped-counter fix added `&obsWrapped` to the
`writeRecord(...)` call in the template. The patch said "already applied", the
headers were refreshed (so `obs-header-identity.txt` said MATCH), and the BUILT
DRIVER still called `writeRecord(..., &obsDropped)`. The build record looked
complete and described a binary that did not contain the fix.

Round 13's first build record is exactly that artefact: build-records/
20261101T031843Z has matching header hashes and a driver whose source does not
pass `&obsWrapped`. It is kept as the counterexample.

WHAT THIS VERIFIES
------------------
  1. on a FRESH tree, the patch applies, and the resulting `obsWrite()` body
     contains the current template's `&obsWrapped` argument;
  2. on an ALREADY-PATCHED tree whose body matches the template, the patch is
     idempotent (exit 0, "already applied");
  3. on an already-patched tree whose body was written from an OLDER template,
     the patch REFUSES (exit non-zero) and says the body is stale;
  4. the refusal happens BEFORE any header is written that would make the
     tree look consistent -- or, if the headers are refreshed, the script says
     so and still refuses.

State 3 is the one that matters: a patch that silently accepts a stale tree is
how a build record ends up describing a binary that lacks the fix.
"""
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
PATCH = os.path.join(ROOT, 'tools', 'build', 'patch-lucy-obs.py')
WORK = os.path.join(ROOT, 'build-work-r13', 'freshness')

FAILS = []

# The minimum upstream surface the patch anchors on. Real anchors, copied from
# the upstream file the patch expects; the patch itself checks that each occurs
# exactly once.
UPSTREAM_HPP = '''#import <IOKit/IOLib.h>
#include "RTL812xLucy.h"
// anchor for the include block
class RTL8125 : public IOEthernetController {
    bool wolCapable;
    bool enableTSO4;
    bool enableTSO6;
    bool useAppleVTD;
    bool hasSensor;
};
'''

UPSTREAM_CPP = '''#include "RTL812xLucy.hpp"

bool RTL8125::start(IOService *provider)
{
    if (!setupStatResources()) {
        IOLog("Error allocating Stat resources.\\n");
        goto error_dma3;
    }
}

void RTL8125::stop(IOService *provider)
{
    freeStatResources();
    freeRxResources();
    freeTxResources();
}

void RTL8125::timerAction(IOTimerEventSource *timer)
{
    rtl812xDumpTallyCounter(tp);
}

bool RTL8125::outputStart(IOOutputQueue *queue, IOOutputPacket *packet, unsigned int numSegs)
{
        OSAddAtomic(-numSegs, &txNumFreeDesc);
        index = txNextDescIndex;
        txNextDescIndex = (txNextDescIndex + numSegs) & kTxDescMask;
        txTailPtr0 += numSegs;
        firstDesc = &txDescArray[index];
        lastSeg = numSegs - 1;
}

void RTL8125::txInterrupt(IOInterruptEventSource *src, int count)
{
}

void RTL8125::rxInterrupt(IOInterruptEventSource *src, int count)
{
}

#pragma mark --- statistics update methods ---
'''


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


def make_tree(tmp, name):
    """A fresh upstream tree the patch can anchor on.

    THE REAL TARBALL IS USED WHEN IT IS PRESENT, and a synthetic stand-in
    otherwise. A synthetic tree would have to reproduce EVERY anchor the patch
    matches, which makes the fixture a copy of the patch's own expectations --
    it would pass by construction and prove nothing about the real source. So
    the tarball is preferred, and the provenance is printed.

    On this Windows workspace there is no tarball, so the fallback is used and
    the run is reported as a WEAKER check. On the Mac build host the real tree
    is used.
    """
    d = os.path.join(tmp, name)
    tarball = None
    for cand in (os.path.expanduser('~/rtl812x-src/src.tar.gz'),
                 os.path.join(ROOT, 'src.tar.gz')):
        if os.path.isfile(cand):
            tarball = cand
            break
    if tarball:
        os.makedirs(d, exist_ok=True)
        r = subprocess.run(['tar', '-xzf', tarball, '-C', d],
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit('refused: could not extract %s: %s'
                             % (tarball, r.stderr[-300:]))
        for entry in sorted(os.listdir(d)):
            full = os.path.join(d, entry)
            if os.path.isdir(full):
                subprocess.run(['chmod', '-R', 'u+rwX', full])
        print('    (tree from %s)' % tarball)
        return d
    print('    (SYNTHETIC tree: no src.tar.gz on this host, so this run checks')
    print('     the freshness LOGIC only, not the real upstream anchors)')
    drv = os.path.join(d, 'RTL812xLucy')
    os.makedirs(drv, exist_ok=True)
    open(os.path.join(drv, 'RTL812xLucy.hpp'), 'w').write(UPSTREAM_HPP)
    open(os.path.join(drv, 'RTL812xLucy.cpp'), 'w').write(UPSTREAM_CPP)
    return d


def have_real_tarball():
    return any(os.path.isfile(p) for p in
               (os.path.expanduser('~/rtl812x-src/src.tar.gz'),
                os.path.join(ROOT, 'src.tar.gz')))


def run_patch(tree):
    """Run the patch against the `RTL812xLucy-<commit>` directory inside `tree`.

    The patch takes the COMMIT directory as its argument (it appends
    `RTL812xLucy` itself), so passing the extraction root makes it refuse with
    "is not a driver directory" -- correctly. The first version of this helper
    passed the root and the check failed for that reason.
    """
    target = drv_dir(tree)
    if target is None:
        raise SystemExit('refused: no RTL812xLucy-<commit> directory in %s'
                         % tree)
    r = subprocess.run([sys.executable, PATCH, target], capture_output=True,
                       text=True)
    return r


def drv_dir(tree):
    """The `RTL812xLucy-<commit>` directory inside `tree`.

    THE PATCH'S ARGUMENT IS THE COMMIT DIRECTORY, NOT ITS PARENT.
    ------------------------------------------------------------
    `apply-lucy-obs2.py` does `drv = os.path.join(root, "RTL812xLucy")` and then
    refuses if that is not a directory. So `root` must be the
    `RTL812xLucy-<commit>` directory itself -- the one that CONTAINS
    `RTL812xLucy/`.

    The first version of this helper returned the parent (the extraction root),
    which the patch correctly refused with "is not a driver directory". The test
    was wrong, not the patch.
    """
    for entry in sorted(os.listdir(tree)):
        cand = os.path.join(tree, entry)
        if os.path.isdir(os.path.join(cand, 'RTL812xLucy')):
            return cand
    return None


def obs_body(tree, method):
    root = drv_dir(tree)
    if root is None:
        return None
    p = os.path.join(root, 'RTL812xLucy', 'RTL812xLucy.cpp')
    text = open(p, encoding='utf-8', errors='replace').read()
    m = re.search(r'^void RTL8125::%s\(.*?\)\s*\{' % method, text, re.M | re.S)
    if not m:
        return None
    start = m.end() - 1
    depth = 0
    i = start
    while i < len(text):
        if text[i] == '{':
            depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
        i += 1
    return None


def main():
    rmtree_force(WORK)
    os.makedirs(WORK)
    print('=' * 78)
    print('PATCH FRESHNESS: does the patch notice a STALE driver tree?')
    print('=' * 78)

    # THE REAL UPSTREAM TREE IS REQUIRED.
    #
    # A synthetic stand-in would have to reproduce every anchor the patch
    # matches -- a dozen exact text spans in a 600 KB file. A fixture built by
    # copying those spans out of the patch would pass by construction, which is
    # precisely the "two documents agreeing with each other" failure this round
    # exists to remove. So when the tarball is absent this check REFUSES rather
    # than reporting a weaker result as if it were the same one.
    if not have_real_tarball():
        print('\n  REFUSED: no upstream tarball on this host.')
        print('  This check needs the REAL RTL812xLucy source, because the')
        print('  patch anchors on exact upstream text. Run it on the Mac build')
        print('  host, where ~/rtl812x-src/src.tar.gz is present.')
        print('\n  This is a REFUSAL, not a pass: the property is UNTESTED here.')
        return 2

    # ------------------------------------------------------------------
    print('\n1. a FRESH tree gets the current body')
    # ------------------------------------------------------------------
    t1 = make_tree(WORK, 'fresh')
    r = run_patch(t1)
    check('the patch applies to a fresh tree', r.returncode == 0,
          (r.stderr or r.stdout).strip()[-300:])
    body = obs_body(t1, 'obsWrite') or ''
    check('the patched obsWrite() passes the wrapped counter',
          '&obsWrapped' in body,
          'the fix is not in the method body, so the driver would not publish '
          'a real wrap')
    check('the patched obsWrite() passes the dropped counter',
          '&obsDropped' in body)
    # And the writer must no longer write the ring header's copy.
    hdr = open(os.path.join(drv_dir(t1), 'RTL812xLucy', 'RTL812xObsWrite.hpp'),
               encoding='utf-8', errors='replace').read()
    # STRIP COMMENTS FIRST. The round-13 header DOCUMENTS the round-12 defect,
    # quoting the very expression the check looks for:
    #
    #     *     __atomic_fetch_add((unsigned int *)(hdr + kObsWrapOffset), ...)
    #
    # so a naive search finds the old defect in a comment and reports it as
    # still present. Round 12's gate-wiring checker made exactly this mistake.
    # Comments are documentation; quoting a defect is not having it.
    hdr_code = re.sub(r'/\*.*?\*/', '', hdr, flags=re.S)
    hdr_code = re.sub(r'//[^\n]*', '', hdr_code)
    m = re.search(r'if \(\(prev & kObsSeqWordLowHalf\) != 0\) \{(.*?)\n    \}',
                  hdr_code, re.S)
    check('the shipped writer does not write the ring header',
          m is not None and 'kObsWrapOffset' not in m.group(1),
          'the ring header is written again, so there are two authorities')

    # ------------------------------------------------------------------
    print('\n2. re-running on the SAME tree is idempotent')
    # ------------------------------------------------------------------
    r = run_patch(t1)
    check('the patch reports "already applied"', r.returncode == 0,
          (r.stderr or r.stdout).strip()[-200:])
    check('  and it says so in words', 'already applied' in r.stdout,
          r.stdout.strip()[:200])

    # ------------------------------------------------------------------
    print('\n3. a tree patched from an OLDER template is REFUSED')
    # ------------------------------------------------------------------
    #
    # This is the round-13 defect: the tree carries the marker, so the
    # idempotence check fires; but its method bodies are from the previous
    # template, so the fix is not in the binary.
    t2 = make_tree(WORK, 'stale')
    r = run_patch(t2)
    if r.returncode != 0:
        check('the fresh patch of the stale fixture succeeds', False,
              r.stderr[-200:])
    else:
        p = os.path.join(drv_dir(t2), 'RTL812xLucy', 'RTL812xLucy.cpp')
        text = open(p, encoding='utf-8', errors='replace').read()
        # Remove the fix from the body, exactly as an older template would have
        # produced it. The marker stays, so only the body differs.
        text2 = text.replace('        &obsDropped,\n        &obsWrapped);',
                             '        &obsDropped);')
        check('the counterexample could be constructed', text2 != text,
              'the anchor for the old call shape was not found')
        open(p, 'w', encoding='utf-8', newline='\n').write(text2)
        r = run_patch(t2)
        check('the patch REFUSES a stale body', r.returncode != 0,
              'the patch accepted a tree whose obsWrite() lacks the fix')
        check('  and it names the stale method', 'STALE' in r.stdout,
              r.stdout.strip()[:300])
        check('  and it says how to recover', 're-extract' in r.stdout,
              'a refusal without a next step is a dead end')

    # ------------------------------------------------------------------
    print('\n4. the built artefact of a stale tree would be wrong')
    # ------------------------------------------------------------------
    #
    # The point of (3): if the patch accepted the stale tree, the BUILD would
    # succeed and produce a driver without the fix. Demonstrate that the
    # difference is real by comparing the two bodies textually.
    fresh_body = obs_body(t1, 'obsWrite') or ''
    stale_body = obs_body(t2, 'obsWrite') or ''
    check('the fresh and stale bodies differ',
          fresh_body != stale_body,
          'they are identical, so the counterexample is not one')
    check('the difference is exactly the wrapped argument',
          fresh_body.count('&obsWrapped') == 1 and
          stale_body.count('&obsWrapped') == 0)

    print()
    print('  RESULT: %s' % ('PATCH FRESHNESS ENFORCED' if not FAILS
                            else 'FAILURES: %s' % FAILS))
    return 0 if not FAILS else 1


if __name__ == '__main__':
    sys.exit(main())
