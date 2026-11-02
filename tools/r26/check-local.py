#!/usr/bin/env python3
"""Focused Round26 software checks; no kext installation or hardware action.

Run from the project root: python3 -B tools/r26/check-local.py
Use --source with a generated RTL812xLucy.cpp to verify real call sites too.
Python >=3.9 and a C++17 compiler are required; CXX overrides discovery.
"""
import argparse
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def run(args, env):
    # Keep the displayed command rooted in this project, including temporary
    # fixture paths. The executing Python/compiler may be system absolute paths.
    shown = [('python3' if str(a) == sys.executable else str(a)) for a in args]
    print('+ ' + ' '.join(shown), flush=True)
    subprocess.run([str(a) for a in args], cwd=ROOT, env=env, check=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', help='generated driver .cpp, relative to project root')
    a = p.parse_args()
    cxx = shlex.split(os.environ.get('CXX', ''))
    if not cxx:
        cxx = [name for name in ('clang++', 'g++') if shutil.which(name)][:1]
    if not cxx:
        raise SystemExit('C++17 compiler required; set CXX or install clang++/g++')
    env = dict(os.environ, CXX=' '.join(shlex.quote(x) for x in cxx),
               PYTHONDONTWRITEBYTECODE='1', ASAN_OPTIONS='detect_leaks=0')
    py = [sys.executable, '-B']
    run(py + ['tools/r21/abi.py', '--check-r26'], env)
    run(py + ['tools/r26/test-protocol.py'], env)
    scratch = ROOT / '_scratch'
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='r26-check-', dir=scratch) as tmp:
        rel = Path(tmp).relative_to(ROOT)
        src = rel / 'driver.cpp'
        exe = rel / ('driver.exe' if os.name == 'nt' else 'driver')
        emit = py + ['tools/r21/test-driver.py', '--emit', src]
        if a.source:
            emit += ['--source', a.source]
        run(emit, env)
        run(cxx + ['-std=c++17', '-w', '-fsanitize=address,undefined',
                   '-I', 'tools/lucy-obs', '-I', 'kext', str(src), '-o', str(exe)], env)
        run([exe], env)
    run(py + ['tools/r26/test-analyzer.py'], env)
    print('Round26 software checks passed; macOS kext build and hardware evidence are separate.')


if __name__ == '__main__':
    main()
