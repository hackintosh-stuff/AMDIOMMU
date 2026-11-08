#!/usr/bin/env python3
"""verify-build-inputs.py -- is the recorded input list the COMPILER'S list?

WHY THIS IS SEPARATE FROM verify-build-record.py
------------------------------------------------
That script drives build-record.sh against stubs, so it can verify the record's
LOGIC but not the CONTENT of a dependency list -- there is no compiler in the
stub workspace. This one runs the real tools/verify/deps.sh on the real toolchain
and checks the properties that make the list trustworthy:

  1. the list comes from `clang -M`, and the raw output is kept;
  2. it contains inputs round 12 omitted entirely:
        tools/build/lucy-kmod-info.cpp        a driver translation unit
        <driver>/linux/*.h              headers the .c files include
        <sdk>/...                       the SDK headers
  3. it contains the observation-log headers the driver ACTUALLY compiles
     (the copies in the driver directory), not only the tool copies;
  4. the tool copy and the driver copy are byte-identical -- the gap that let a
     stale header be compiled while a fresh one was hashed;
  5. the compile/link command lines are recorded;
  6. the SDK is identified (version + hash) rather than copied;
  7. the flags deps.sh uses are the SAME flags the build scripts use. This is
     the property that stops the dependency list describing a different build:
     deps.sh copies the flag strings, so a change in build-m1a.sh or
     build-lucy.sh without a matching change here is a failure.

Property 7 is the one that decays silently, so it is checked by reading both
scripts and comparing the flag strings character for character.

RUN THIS ON THE MAC BUILD HOST (it needs clang and the driver baseline).
"""
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
DEPS = os.path.join(ROOT, 'tools', 'verify', 'deps.sh')
WORK = os.path.join(ROOT, 'build-work-r13', 'inputs')

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


def script_vars(path):
    """Collect the plain `NAME=value` assignments a script makes before use.

    WHY THIS IS NEEDED
    -----------------
    The two scripts use the name `SDK` for DIFFERENT directories:
    build-m1a.sh's `SDK` is the macOS SDK, build-lucy.sh's `SDK` is the
    MacKernelSDK. Both are correct in their own file. A literal string
    comparison of the flag bodies would therefore report a difference that does
    not exist -- and, worse, a REAL difference could hide behind it.

    So each script's variables are resolved to their literal values first, and
    the comparison is between the resulting command lines. Only simple
    `NAME="..."` and `NAME=word` assignments are resolved; anything computed at
    run time is left as its source text, which makes the comparison stricter
    (a computed value that differs is still a difference).
    """
    text = open(path, encoding='utf-8', errors='replace').read()
    out = {}
    for m in re.finditer(r'^([A-Za-z_][A-Za-z0-9_]*)=(?:"(.*?)"|(\S*))\s*$',
                         text, re.M | re.S):
        name = m.group(1)
        val = m.group(2) if m.group(2) is not None else m.group(3)
        out[name] = ' '.join(val.replace('\\\n', ' ').split())
    return out


def resolve(flags, variables, depth=0):
    """Substitute $NAME / ${NAME} with the script's own literal value."""
    if depth > 5:
        return flags

    def sub(m):
        name = m.group(1) or m.group(2)
        if name in variables:
            return resolve(variables[name], variables, depth + 1)
        return m.group(0)

    return re.sub(r'\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))',
                  sub, flags)


def flag_string(path, name):
    """Extract a shell variable assignment's text, with continuations joined.

    The naive `^NAME="([^"]*)"` does NOT match the multi-line form the build
    scripts use when `.` cannot cross newlines: the first version of this
    function returned None for BOTH files, and the check reported "present in
    both: False" -- a test that failed for a parsing reason rather than a real
    difference, which is the same class of error as reading a comment as code.
    """
    text = open(path, encoding='utf-8', errors='replace').read()
    m = re.search(r'^%s="(.*?)"' % re.escape(name), text, re.M | re.S)
    if not m:
        return None
    body = m.group(1).replace('\\\n', ' ')
    return ' '.join(body.split())


def normalise(flags):
    """Collapse whitespace and sort the -I/-D/-include tokens.

    ORDER of include paths matters for resolution, so they are NOT reordered;
    only redundant whitespace and line continuations are normalised. Two flag
    strings are equal only if they would drive the compiler identically.
    """
    return ' '.join(flags.split())


def main():
    if not os.path.exists(DEPS):
        print('no deps.sh at %s' % DEPS)
        return 2
    if not shutil.which('clang') and not os.path.exists('/usr/bin/clang'):
        print('REFUSED: no clang on this host. Run this on the Mac build host;')
        print('         it is NOT a pass to skip it.')
        return 2

    rmtree_force(WORK)
    os.makedirs(WORK)

    print('=' * 78)
    print('BUILD INPUTS: is the recorded list the compiler\'s list?')
    print('=' * 78)

    r = subprocess.run(['sh', DEPS, WORK], capture_output=True, text=True,
                       cwd=ROOT)
    if r.returncode != 0:
        check('deps.sh completes', False,
              (r.stderr or r.stdout).strip()[-400:])
        print('\n  RESULT: FAILURES')
        return 1
    check('deps.sh completes', True)

    # ------------------------------------------------------------------
    print('\n1. the list comes from the compiler')
    # ------------------------------------------------------------------
    raw = os.path.join(WORK, 'probe-deps.raw.txt')
    check('the raw clang -M output is kept', os.path.exists(raw))
    rt = open(raw, encoding='utf-8', errors='replace').read() \
        if os.path.exists(raw) else ''
    check('the raw output has make-style rules',
          re.search(r'^[^\s:]+\.cpp:\s', rt, re.M) is not None or
          ': ' in rt,
          'no dependency rule found')
    for stem in ('probe', 'lucy'):
        lst = os.path.join(WORK, stem + '-inputs.list')
        man = os.path.join(WORK, stem + '-inputs.sha256')
        check('%s: the parsed list exists' % stem, os.path.exists(lst))
        check('%s: the hashed manifest exists' % stem, os.path.exists(man))
        if os.path.exists(man):
            mt = open(man, encoding='utf-8', errors='replace').read()
            check('%s: the manifest says it is compiler-derived' % stem,
                  'clang -M' in mt)

    # ------------------------------------------------------------------
    print('\n2. inputs round 12 omitted entirely')
    # ------------------------------------------------------------------
    lp = os.path.join(WORK, 'lucy-inputs.list')
    lucy = [l.strip() for l in open(lp)] if os.path.exists(lp) else []
    joined = '\n'.join(lucy)
    check('tools/build/lucy-kmod-info.cpp is listed',
          any('lucy-kmod-info.cpp' in f for f in lucy),
          'this is a real translation unit of the driver build')
    check('the driver\'s linux/ headers are listed',
          any('/linux/' in f for f in lucy),
          'the .c files include these')
    check('the observation-log headers the driver compiles are listed',
          any('RTL812xObsLog.hpp' in f for f in lucy) and
          any('RTL812xObsWrite.hpp' in f for f in lucy),
          'round 12 hashed only the TOOL copies')

    pp = os.path.join(WORK, 'probe-inputs.list')
    probe = [l.strip() for l in open(pp)] if os.path.exists(pp) else []
    check('the probe\'s SDK headers are listed',
          any('/Kernel.framework/' in f or '/MacOSX.sdk/' in f for f in probe),
          'round 12 recorded no SDK headers at all')

    # ------------------------------------------------------------------
    print('\n3. the two header copies are the same file')
    # ------------------------------------------------------------------
    #
    # THE GAP: `tools/lucy-obs/*.hpp` are hashed, but the build compiles the
    # COPIES the patch installs into the driver directory. A header changed in
    # the tool directory and not re-applied leaves the manifest describing a
    # file the build never read.
    hi = os.path.join(WORK, 'obs-header-identity.txt')
    ht = open(hi, encoding='utf-8', errors='replace').read() \
        if os.path.exists(hi) else ''
    check('the header identity file exists', os.path.exists(hi))
    check('both headers MATCH between tool and driver',
          ht.count('MATCH') == 2 and 'MISMATCH' not in ht,
          ht.strip()[:300])

    # And the driver copy is what the compiler listed.
    for name in ('RTL812xObsLog.hpp', 'RTL812xObsWrite.hpp'):
        listed = [f for f in lucy if f.endswith(name)]
        driver_side = [f for f in listed if '/RTL812xLucy/' in f]
        check('%s is listed from the DRIVER directory' % name,
              bool(driver_side),
              'listed: %s' % listed)

    # ------------------------------------------------------------------
    print('\n4. the command lines are recorded')
    # ------------------------------------------------------------------
    bc = os.path.join(WORK, 'build-commands.txt')
    bt = open(bc, encoding='utf-8', errors='replace').read() \
        if os.path.exists(bc) else ''
    check('build-commands.txt exists', os.path.exists(bc))
    for want in ('clang++', 'clang -x c', 'xcrun ld -kext'):
        check('it records %r' % want, want in bt)

    # ------------------------------------------------------------------
    print('\n5. the SDK is identified, not copied')
    # ------------------------------------------------------------------
    si = os.path.join(WORK, 'sdk-identity.txt')
    st = open(si, encoding='utf-8', errors='replace').read() \
        if os.path.exists(si) else ''
    check('sdk-identity.txt exists', os.path.exists(si))
    check('the SDK version is recorded', 'sdk_version' in st)
    check('the SDK settings plist hash is recorded',
          'SDKSettings.plist_sha256' in st)
    check('the MacKernelSDK tree hash is recorded',
          'mackernelsdk_tree_sha256' in st)
    # And the SDK headers are NOT in the record directory (they are gigabytes).
    sdk_files = [f for f in os.listdir(WORK) if f.startswith('MacOSX')]
    check('no SDK is copied into the record', not sdk_files,
          'found: %s' % sdk_files)

    # ------------------------------------------------------------------
    print('\n6. deps.sh uses the SAME flags the build scripts use')
    # ------------------------------------------------------------------
    #
    # THE PROPERTY THAT DECAYS SILENTLY. deps.sh copies the flag strings rather
    # than sourcing the build scripts (they build when run). The duplication is
    # therefore checked here, character for character after whitespace
    # normalisation: a flag added to a build script without a matching change in
    # deps.sh means the dependency list describes a DIFFERENT build.
    pairs = [
        ('tools/build/build-probe.sh', 'CFLAGS', 'tools/verify/deps.sh', 'PROBE_CFLAGS'),
        ('tools/build/lucy.sh', 'CFLAGS', 'tools/verify/deps.sh', 'LUCY_CFLAGS'),
        ('tools/build/lucy.sh', 'CFLAGS_C', 'tools/verify/deps.sh',
         'LUCY_CFLAGS_C'),
    ]
    for build_script, build_var, deps_script, deps_var in pairs:
        a = flag_string(os.path.join(ROOT, build_script), build_var)
        b = flag_string(os.path.join(ROOT, deps_script), deps_var)
        if a is None or b is None:
            check('%s:%s is present in both' % (build_script, build_var),
                  False, 'a=%r b=%r' % (a is not None, b is not None))
            continue
        # Resolve each script's OWN variable definitions first: the name `SDK`
        # means different directories in the two build scripts, and comparing
        # the raw text would report that naming difference as a flag difference.
        av = resolve(a, script_vars(os.path.join(ROOT, build_script)))
        bv = resolve(b, script_vars(os.path.join(ROOT, deps_script)))
        same = normalise(av) == normalise(bv)
        check('%s %s == deps.sh %s' % (build_script, build_var, deps_var), same,
              'they differ, so the dependency list describes a different build')
        if not same:
            ta, tb = normalise(av).split(), normalise(bv).split()
            for i in range(min(len(ta), len(tb))):
                if ta[i] != tb[i]:
                    print('        first difference at token %d: %r vs %r'
                          % (i, ta[i], tb[i]))
                    break
            else:
                print('        one string is a prefix of the other: %d vs %d '
                      'tokens' % (len(ta), len(tb)))

    print()
    print('  RESULT: %s' % ('BUILD INPUTS TRACEABLE' if not FAILS
                            else 'FAILURES: %s' % FAILS))
    return 0 if not FAILS else 1


if __name__ == '__main__':
    sys.exit(main())
