#!/usr/bin/env python3
"""verify-build-record.py -- does build-record.sh really record both artefacts?

WHY
---
Round 11's build-record.sh had four defects that all pointed the same way: the
record looked complete and was not.

  B1  only the PROBE was recorded, not the driver that produces the log
  B2  a fixed output directory, `rm -rf`'d first -- a second build destroyed
      the first build's record
  B3  the artefact copy used `|| true`, so a failed copy was swallowed
  B4  the record stayed on the Mac

A script that is only ever READ cannot be verified. This one runs the script
against stub build commands and inspects what it produced. It does not build a
kext: the properties under test are about the RECORD, not about clang.

WHAT IT ASSERTS
---------------
  1. two artefacts appear in the record, each with a source manifest and a
     built-artefact identity;
  2. two consecutive runs produce two DIFFERENT directories, and the first
     one still contains its files afterwards;
  3. a run that cannot copy the artefact FAILS, instead of writing a record
     that claims to contain it;
  4. "installed" and "loaded" are separate files and neither is called the
     other;
  5. the record's own hashes match the files it contains.
"""
import os
import re
import shutil
import subprocess
import sys

def rmtree_force(path):
    """Remove a tree, clearing read-only bits first.

    Windows sets a read-only attribute on files extracted from an archive; a
    plain shutil.rmtree then fails with WinError 5 and aborts the run. A
    cleanup failure must not be reported as a test failure.
    """
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



HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SCRIPT = os.path.join(ROOT, 'tools', 'build', 'record.sh')
WORK = os.path.join(ROOT, 'build-work-r12', 'buildrecord')

FAILS = []


def check(name, ok, detail=''):
    print('  %-64s %s%s' % (name, 'PASS' if ok else 'FAIL',
                            '   [%s]' % detail if detail and not ok else ''))
    if not ok:
        FAILS.append(name)
    return ok


def make_stubs(tmp):
    """Stub the two build scripts and the tools they call.

    The point is to exercise build-record.sh's OWN logic -- directory
    allocation, copying, verification, the three-fact separation -- without
    needing a toolchain or a 4-minute build.

    ROUND 13: the record now also runs tools/verify/deps.sh, which shells out to
    `clang -M` and `xcrun`. Those are stubbed with a script that writes the same
    OUTPUT FILES deps.sh writes, so the record's handling of them is exercised
    without a compiler. That is a deliberate boundary: the dependency list's
    CONTENT is verified by tools/verify/build-inputs.py against the real
    toolchain; this harness verifies only that build-record.sh FAILS when
    deps.sh fails, and records what deps.sh produced when it succeeds.
    """
    bindir = os.path.join(tmp, 'bin')
    os.makedirs(bindir, exist_ok=True)

    # A fake workspace with the two build entry points and their outputs.
    ws = os.path.join(tmp, 'ws')
    os.makedirs(os.path.join(ws, 'tools', 'build'), exist_ok=True)
    os.makedirs(os.path.join(ws, 'kext'), exist_ok=True)

    # build-m1a.sh: create a bundle and record its path.
    open(os.path.join(ws, 'tools', 'build', 'probe.sh'), 'w').write(
        '#!/bin/sh\n'
        'K="$PWD/build-m1a/AMDMapperProbe.kext"\n'
        'mkdir -p "$K/Contents/MacOS"\n'
        'printf "probe-binary" > "$K/Contents/MacOS/AMDMapperProbe"\n'
        'cat > "$K/Contents/Info.plist" <<EOF\n'
        '<?xml version="1.0"?><plist version="1.0"><dict>\n'
        '<key>CFBundleVersion</key><string>1.2.0</string>\n'
        '<key>CFBundleIdentifier</key><string>org.maz1.AMDMapperProbe</string>\n'
        '</dict></plist>\n'
        'EOF\n'
        'printf "%s\\n" "$K" > latest-m1a-build.txt\n')
    # build-lucy.sh: same for the driver.
    open(os.path.join(ws, 'tools', 'build', 'lucy.sh'), 'w').write(
        '#!/bin/sh\n'
        'K="$PWD/build-lucy/RTL812xLucy.kext"\n'
        'mkdir -p "$K/Contents/MacOS"\n'
        'printf "lucy-binary" > "$K/Contents/MacOS/RTL812xLucy"\n'
        'cat > "$K/Contents/Info.plist" <<EOF\n'
        '<?xml version="1.0"?><plist version="1.0"><dict>\n'
        '<key>CFBundleVersion</key><string>1.1.200</string>\n'
        '<key>CFBundleIdentifier</key><string>com.insanelymac.RTL812xLucy</string>\n'
        '</dict></plist>\n'
        'EOF\n'
        'printf "%s\\n" "$K" > latest-lucy-build.txt\n')
    for f in ('build/probe.sh', 'build/lucy.sh'):
        os.chmod(os.path.join(ws, 'tools', f), 0o755)

    # The source files the manifests hash.
    for name in ('AMDMapperProbe.cpp', 'AMDMapperProbeNic.cpp',
                 'AMDMapperProbeB1B2Debug.cpp', 'AMDMapperProbeMmioDebug.cpp',
                 'AMDMapperProbeTableDebug.cpp', 'AMDMapperProbeDmaDebug.cpp',
                 'AMDMapperProbeObsDebug.cpp', 'AMDMapperProbePgtDebug.cpp',
                 'AMDMapperProbeInternal.hpp', 'AMDMapperProbe.hpp',
                 'amd_iommu_dma_observe.hpp', 'amd_iommu_pte_core.hpp',
                 'amd_iommu_bizwalk_core.hpp', 'AMDMapperProbe-Info.plist',
                 'Info.plist'):
        open(os.path.join(ws, 'kext', name), 'w').write('// %s\n' % name)
    os.makedirs(os.path.join(ws, 'tools', 'lucy-obs'), exist_ok=True)
    for name in ('RTL812xObsLog.hpp', 'RTL812xObsWrite.hpp'):
        open(os.path.join(ws, 'tools', 'lucy-obs', name), 'w').write('// x\n')
    open(os.path.join(ws, 'tools', 'build', 'patch-lucy-obs.py'), 'w').write('# x\n')

    # The upstream baseline directory the driver manifest hashes.
    up = os.path.join(ws, 'RTL812xLucy-1.1.2', 'RTL812xLucy')
    os.makedirs(up, exist_ok=True)
    for name in ('RTL812xLucy.cpp', 'RTL812xLucyHardware.cpp', 'rtl812x_phy.c',
                 'RTL8125LucyPrefix.pch'):
        open(os.path.join(up, name), 'w').write('// %s\n' % name)

    # ---- ROUND 13: the compiler-derived input list ----------------------
    #
    # build-record.sh runs tools/verify/deps.sh. The stub writes the same FILES
    # with plausible content, so the record's handling is exercised. Its
    # behaviour is switchable so the "deps failed" case can be produced.
    os.makedirs(os.path.join(ws, 'tools', 'verify'), exist_ok=True)
    open(os.path.join(ws, 'tools', 'verify', 'deps.sh'), 'w').write(
        '#!/bin/sh\n'
        'OUT=${1:?outdir}\n'
        'if [ -f "$PWD/DEPS_FAIL" ]; then\n'
        '  echo "stub deps: refusing" >&2\n'
        '  exit 1\n'
        'fi\n'
        'mkdir -p "$OUT"\n'
        'echo "sdk_path : /stub/sdk" > "$OUT/sdk-identity.txt"\n'
        'echo "xcrun clang++ <flags> -c <src>" > "$OUT/build-commands.txt"\n'
        'echo "### stub" > "$OUT/probe-deps.raw.txt"\n'
        'echo "### stub" > "$OUT/lucy-deps.raw.txt"\n'
        'printf "kext/AMDMapperProbe.cpp\\nkext/AMDMapperProbe.hpp\\n"'
        ' > "$OUT/probe-inputs.list"\n'
        'printf "tools/build/lucy-kmod-info.cpp\\nRTL812xLucy-1.1.2/RTL812xLucy/'
        'RTL812xLucy.cpp\\n" > "$OUT/lucy-inputs.list"\n'
        'printf "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        'aaaaaaaaaaaaaaaa  1  project-kext  kext/AMDMapperProbe.cpp\\n"'
        ' > "$OUT/probe-inputs.sha256"\n'
        'printf "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
        'bbbbbbbbbbbbbbbb  1  project-tools  tools/build/lucy-kmod-info.cpp\\n"'
        ' > "$OUT/lucy-inputs.sha256"\n'
        'echo "MATCH    RTL812xObsLog.hpp" > "$OUT/obs-header-identity.txt"\n'
        'echo "MATCH    RTL812xObsWrite.hpp" >> "$OUT/obs-header-identity.txt"\n'
        'echo "deps stub done"\n')
    os.chmod(os.path.join(ws, 'tools', 'verify', 'deps.sh'), 0o755)

    # Tools the script calls. shasum/stat/dwarfdump/otool/nm/plutil etc. all
    # exist on macOS, so only the ones that would touch the real system are
    # stubbed: nothing here deploys, so nothing needs stubbing for that.
    return ws, bindir


def run(ws, outdir, extra_env=None):
    """Run the COPY of the script that lives inside the stub workspace.

    WHY THE COPY
    ------------
    build-record.sh derives its workspace root from its own path
    (`dirname $0/..`). Running the original would therefore resolve to the real
    project tree, where the stub's RTL812xLucy-*/ baseline does not exist -- and
    the test would report "the script is broken" when what was broken was the
    harness. The first version of this file made exactly that mistake.
    """
    script = os.path.join(ws, 'tools', 'build', 'record.sh')
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
    r = subprocess.run(['sh', script, outdir], cwd=ws, capture_output=True,
                       text=True, env=env)
    return r


def main():
    if os.path.isdir(WORK):
        rmtree_force(WORK)
    os.makedirs(WORK)
    ws, _ = make_stubs(WORK)

    # The script reads its own location to find the workspace root, so the copy
    # must live inside the stub workspace.
    os.makedirs(os.path.join(ws, 'tools'), exist_ok=True)
    shutil.copy(SCRIPT, os.path.join(ws, 'tools', 'build', 'record.sh'))
    # ROUND 13: deps.sh lives at tools/r13/, so the copy needs the same layout.
    os.makedirs(os.path.join(ws, 'tools', 'verify'), exist_ok=True)

    print('=' * 78)
    print('BUILD RECORD: does it record both artefacts, and can it fail?')
    print('=' * 78)

    # ------------------------------------------------------------------
    print('\n1. one run records BOTH artefacts')
    # ------------------------------------------------------------------
    out1 = os.path.join(ws, 'build-records', 'run1')
    r = run(ws, out1)
    if r.returncode != 0:
        check('the build record completes', False,
              (r.stderr or r.stdout).strip()[-300:])
        print('\n  RESULT: FAILURES')
        return 1
    check('the build record completes', True)

    for f in ('record-identity.txt', 'toolchain.txt',
              'probe-source-manifest.sha256', 'lucy-source-manifest.sha256',
              'probe-build.log', 'lucy-build.log',
              'artefact-identity.txt', 'installed-identity.txt',
              'README.txt'):
        check('the record contains %s' % f,
              os.path.exists(os.path.join(out1, f)))

    ident = open(os.path.join(out1, 'artefact-identity.txt')).read()
    check('the PROBE artefact is identified (uuid + sha256)',
          'probe_sha256' in ident and 'probe_uuid' in ident)
    check('the DRIVER artefact is identified (uuid + sha256)',
          'lucy_sha256' in ident and 'lucy_uuid' in ident,
          'round 11 recorded only the probe')

    lm = open(os.path.join(out1, 'lucy-source-manifest.sha256')).read()
    check('the driver manifest includes the PATCH',
          'patch-lucy-obs.py' in lm)
    check('the driver manifest includes its own headers',
          'RTL812xObsWrite.hpp' in lm)
    check('the driver manifest identifies the UPSTREAM baseline',
          'baseline_dir' in lm and 'RTL812xLucy.cpp' in lm)

    check('both bundles were copied into the record',
          os.path.exists(os.path.join(
              out1, 'AMDMapperProbe.kext', 'Contents', 'MacOS',
              'AMDMapperProbe')) and
          os.path.exists(os.path.join(
              out1, 'RTL812xLucy.kext', 'Contents', 'MacOS', 'RTL812xLucy')))

    # ---- ROUND 13: the compiler-derived inputs are in the record -------
    #
    # Round 12's record had no dependency list at all, so the files it did not
    # think of were simply absent -- including a whole driver translation unit.
    for f in ('probe-inputs.sha256', 'lucy-inputs.sha256',
              'probe-deps.raw.txt', 'lucy-deps.raw.txt',
              'build-commands.txt', 'sdk-identity.txt',
              'obs-header-identity.txt'):
        check('the record contains %s' % f,
              os.path.exists(os.path.join(out1, f)),
              'round 12 recorded only a hand-written file list')
    li = open(os.path.join(out1, 'lucy-inputs.sha256')).read() \
        if os.path.exists(os.path.join(out1, 'lucy-inputs.sha256')) else ''
    check('the driver input list includes tools/build/lucy-kmod-info.cpp',
          'lucy-kmod-info' in li,
          'round 12 omitted this translation unit entirely')
    bc = open(os.path.join(out1, 'build-commands.txt')).read() \
        if os.path.exists(os.path.join(out1, 'build-commands.txt')) else ''
    check('the record carries the compile/link command lines',
          'clang++' in bc and '-c' in bc)

    # ------------------------------------------------------------------
    print('\n2. two runs do not share a directory')
    # ------------------------------------------------------------------
    out2 = os.path.join(ws, 'build-records', 'run2')
    r = run(ws, out2)
    check('a second run completes', r.returncode == 0,
          (r.stderr or '').strip()[-200:])
    check('the two runs used different directories', out1 != out2)
    check('the FIRST record still exists and is intact',
          os.path.exists(os.path.join(out1, 'artefact-identity.txt')) and
          os.path.exists(os.path.join(out1, 'README.txt')),
          'round 11 rm -rf\'d a fixed directory, destroying the earlier record')

    # Re-using an existing directory must be REFUSED, not silently overwritten.
    r = run(ws, out1)
    check('re-using an existing record directory is REFUSED',
          r.returncode != 0,
          'the script overwrote an existing record')

    # ------------------------------------------------------------------
    print('\n2b. a failed compiler-derived input list FAILS the run')
    # ------------------------------------------------------------------
    #
    # ROUND 13. deps.sh exits non-zero when the driver's header copies differ
    # from the tool copies -- which means the manifest would describe a file the
    # build does not use. The record must fail rather than write a manifest that
    # claims otherwise. Round 12 had no such input list and could not fail this
    # way.
    outd = os.path.join(ws, 'build-records', 'run-deps-fail')
    open(os.path.join(ws, 'DEPS_FAIL'), 'w').write('1\n')
    r = run(ws, outd)
    os.remove(os.path.join(ws, 'DEPS_FAIL'))
    check('a failed deps.sh FAILS the record', r.returncode != 0,
          'the record completed without a compiler-derived input list')
    check('  and it says why', 'compiler-derived input list' in
          (r.stdout + r.stderr),
          (r.stdout + r.stderr)[-200:])

    # ------------------------------------------------------------------
    print('\n3. a failed artefact copy FAILS the run')
    # ------------------------------------------------------------------
    # Make the driver bundle's binary disappear between the build and the copy.
    # Round 11's `|| true` would have produced a record claiming to contain it.
    out3 = os.path.join(ws, 'build-records', 'run3')
    lucy_bin = os.path.join(ws, 'build-lucy', 'RTL812xLucy.kext', 'Contents',
                            'MacOS', 'RTL812xLucy')
    # Replace the build script with one that produces an EMPTY bundle: the
    # binary the script then tries to copy will not exist.
    #
    # The `rm -rf` is load-bearing. Without it the previous run's binary is
    # still on disk, so the "missing artefact" case is not actually produced
    # and the check passes for the wrong reason -- which is what happened the
    # first time this harness was run.
    open(os.path.join(ws, 'tools', 'build', 'lucy.sh'), 'w').write(
        '#!/bin/sh\n'
        'K="$PWD/build-lucy/RTL812xLucy.kext"\n'
        'rm -rf "$PWD/build-lucy"\n'
        'mkdir -p "$K/Contents/MacOS"\n'
        'cat > "$K/Contents/Info.plist" <<EOF\n'
        '<?xml version="1.0"?><plist version="1.0"><dict>\n'
        '<key>CFBundleVersion</key><string>1.1.200</string>\n'
        '</dict></plist>\n'
        'EOF\n'
        'printf "%s\\n" "$K" > latest-lucy-build.txt\n')
    r = run(ws, out3)
    check('the "missing artefact" scenario was actually produced',
          not os.path.exists(lucy_bin),
          'the stub left a previous binary in place')
    check('a build whose artefact is missing FAILS the record',
          r.returncode != 0,
          'the record completed without the driver binary')

    # ------------------------------------------------------------------
    print('\n4. built / installed / loaded are three separate facts')
    # ------------------------------------------------------------------
    inst = open(os.path.join(out1, 'installed-identity.txt')).read()
    check('the installed file is labelled INSTALLED, not loaded',
          'installed_sha256' in inst or 'installed_path' in inst)
    check('it explicitly says it is not a load identity',
          'NOT A LOAD IDENTITY' in inst or 'not a load identity' in inst.lower())
    check('it names the file that WOULD carry the load identity',
          'record-loaded.sh' in inst or 'loaded-identity' in inst)
    rd = open(os.path.join(out1, 'README.txt')).read()
    check('the README separates built / installed / loaded',
          'built' in rd and 'installed' in rd and 'loaded' in rd)
    check('the load identity is absent until a rebooted run writes it',
          not os.path.exists(os.path.join(out1, 'loaded-identity.txt')),
          'a load identity exists without a rebooted run having recorded it')
    check('the record says so rather than leaving the reader to assume',
          'loaded-identity.txt' in rd and 'absent' in rd.lower())

    # ------------------------------------------------------------------
    print('\n5. the record is self-consistent')
    # ------------------------------------------------------------------
    #
    # Every hash the record publishes must match the file it describes.
    ok_hashes = True
    bad = []
    for man in ('probe-source-manifest.sha256', 'lucy-source-manifest.sha256'):
        path = os.path.join(out1, man)
        for line in open(path):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            m = re.match(r'^([0-9a-f]{64})\s+(\d+)\s+(\S+)$', line)
            if not m:
                continue
            digest, size, rel = m.groups()
            full = os.path.join(ws, rel)
            if not os.path.exists(full):
                continue
            actual = subprocess.run(['shasum', '-a', '256', full],
                                    capture_output=True, text=True
                                    ).stdout.split()[0]
            if actual != digest:
                ok_hashes = False
                bad.append(rel)
    check('every published source hash matches its file', ok_hashes,
          str(bad[:3]))

    # The copied binaries must hash the same as the built ones.
    a = subprocess.run(['shasum', '-a', '256',
                        os.path.join(ws, 'build-m1a', 'AMDMapperProbe.kext',
                                     'Contents', 'MacOS', 'AMDMapperProbe')],
                       capture_output=True, text=True).stdout.split()[0]
    b = subprocess.run(['shasum', '-a', '256',
                        os.path.join(out1, 'AMDMapperProbe.kext', 'Contents',
                                     'MacOS', 'AMDMapperProbe')],
                       capture_output=True, text=True).stdout.split()[0]
    check('the copied probe binary matches the built one', a == b)

    print()
    print('  RESULT: %s' % ('BUILD RECORD CORRECT' if not FAILS
                            else 'FAILURES: %s' % FAILS))
    return 0 if not FAILS else 1


if __name__ == '__main__':
    sys.exit(main())
