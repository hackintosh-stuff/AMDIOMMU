#!/usr/bin/env python3
"""Focused Round29 software checks; no device, install or reboot actions.

The C++ harnesses compile real driver/backend bodies with host plumbing.
They do not replace a macOS kext build or the one required hardware run.
Python 3.9+ and a C++17 compiler are required.
"""
import argparse
import ast
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def run(args, env):
    shown = [('python3' if str(a) == sys.executable else str(a)) for a in args]
    print('+ ' + ' '.join(shown), flush=True)
    subprocess.run([str(a) for a in args], cwd=str(ROOT), env=env, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', help='generated driver cpp, relative to repository root')
    args = parser.parse_args()
    if args.source:
        source = Path(args.source)
        if source.is_absolute():
            raise ValueError('--source must be repository relative')
        (ROOT / source).resolve().relative_to(ROOT)
    cxx = shlex.split(os.environ.get('CXX', ''))
    if not cxx:
        cxx = [name for name in ('clang++', 'g++') if shutil.which(name)][:1]
    if not cxx:
        raise SystemExit('C++17 compiler required; set CXX')
    env = dict(os.environ, CXX=' '.join(shlex.quote(x) for x in cxx),
               PYTHONDONTWRITEBYTECODE='1', ASAN_OPTIONS='detect_leaks=0')
    for path in sorted((ROOT / 'tools/r27').glob('*.py')):
        data = path.read_bytes()
        if b'\r' in data:
            raise ValueError('Mac source must use LF: ' + path.name)
        ast.parse(data.decode('utf-8'), filename=path.name, feature_version=(3, 9))
    py = [sys.executable, '-B']
    run(py + ['tools/r21/abi.py', '--check-r29'], env)
    # Normal main traffic plus the single final-batch/done handshake regression.
    run(py + ['tools/r27/test-protocol.py',
              'ProtocolTests.test_all_8192_send_all_then_receive',
              'ProtocolTests.test_last_tail_batch_finishes_before_done'], env)
    rx = py + ['tools/r27/test-driver.py']
    if args.source:
        rx += ['--source', args.source]
    run(rx, env)
    run(py + ['tools/r27/test-backend.py'], env)
    # Preserve the established all-TX path with one existing real-body run.
    scratch = ROOT / '_scratch'
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='r27-tx-', dir=str(scratch)) as tmp:
        rel = Path(tmp).relative_to(ROOT)
        cpp, exe = rel / 'tx.cpp', rel / ('tx.exe' if os.name == 'nt' else 'tx')
        emit = py + ['tools/r21/test-driver.py', '--emit', cpp]
        if args.source:
            emit += ['--source', args.source]
        run(emit, env)
        run(cxx + ['-std=c++17', '-w', '-fsanitize=address,undefined',
                   '-I', 'tools/lucy-obs', '-I', 'kext', cpp, '-o', exe], env)
        run([exe], env)
    run(py + ['tools/r27/test-analyzer.py',
              'AnalyzerTests.test_rx64_full_lifecycle_with_actual_headers_and_real_logs'], env)
    print('Round29 focused software checks passed; macOS build and hardware acceptance remain separate.')


if __name__ == '__main__':
    main()
