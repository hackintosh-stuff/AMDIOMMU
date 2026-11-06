#!/usr/bin/env python3
"""R67: tools-only post-wake traffic. No deployment, build or reboot commands."""
from pathlib import Path
import runpy
import sys

HERE = Path(__file__).resolve()
PREVIOUS = runpy.run_path(str(HERE.parents[1] / 'pm/run.py'))
SHARED = PREVIOUS['R64']['previous']['shared']
# Retain the actual binary source lineage (R66-2); these binaries are not rebuilt.
# a4778b1 is the accepted source baseline for this tools-only patch.
RUN = PREVIOUS['RUN']._replace(
    number=67, token=0x6700de67, runner=HERE,
    installed_client_dependency='0.74.0', retained_lucy_dependency='0.70.0')
NATIVE = ('peer', 'load', 'capture', 'analyze')
POSTWAKE = ('prepare', 'sustain-peer', 'sustain', 'finish')


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in NATIVE + POSTWAKE:
        print('usage: run.py {%s} [arguments]' % ','.join(POSTWAKE + NATIVE))
        return 0 if sys.argv[1:] in (['-h'], ['--help']) else 2
    if sys.argv[1] in NATIVE:
        return SHARED['main'](RUN)
    action = sys.argv.pop(1)
    if action == 'sustain-peer':
        return runpy.run_path(str(HERE.with_name('transport.py')))['peer_main'](RUN.token)
    return runpy.run_path(str(HERE.with_name('postwake.py')))['main'](action)


if __name__ == '__main__':
    raise SystemExit(main())
