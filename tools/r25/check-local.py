#!/usr/bin/env python3
"""Focused round25 software validation. Does not install, load or reboot a kext.

Uses the real generated driver bodies, the command/backend harness and current
protocol/analyzer tests. A successful result is software evidence only.
Requires Python >=3.9 and a C++17 compiler; CXX overrides clang++/g++ discovery.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def run(args, env=None):
    print('+ ' + ' '.join(str(a) for a in args), flush=True)
    subprocess.run([str(a) for a in args], cwd=ROOT, env=env, check=True)


def main():
    cxx = os.environ.get('CXX') or shutil.which('clang++') or shutil.which('g++')
    if not cxx:
        raise SystemExit('C++17 compiler required; set CXX or install clang++/g++')
    env = dict(os.environ, CXX=cxx, PYTHONDONTWRITEBYTECODE='1')
    py = [sys.executable, '-B']
    run(py + ['tools/r21/abi.py', '--check-r25'], env)
    run(py + ['tools/r21/test-protocol.py'], env)
    with tempfile.TemporaryDirectory(prefix='amd-r25-') as tmp:
        src = Path(tmp) / 'driver.cpp'
        exe = Path(tmp) / ('driver.exe' if os.name == 'nt' else 'driver')
        run(py + ['tools/r21/test-driver.py', '--emit', src], env)
        run([cxx, '-std=c++17', '-w', '-fsanitize=address,undefined',
             '-I', ROOT / 'tools/lucy-obs', '-I', ROOT / 'kext', src, '-o', exe], env)
        # Existing native fixtures intentionally retain objects. Address/UB
        # checks remain enabled; fixture leak accounting is outside this test.
        run([exe], dict(env, ASAN_OPTIONS='detect_leaks=0'))
    run(py + ['tools/r25/backend-host-test.py', '--compiler', cxx, '--sanitize'],
        dict(env, ASAN_OPTIONS='detect_leaks=0'))
    run(py + ['tools/r25/test-analyzer.py'], env)
    print('Round25 local software checks passed. macOS build and hardware run remain separate.')


if __name__ == '__main__':
    main()
