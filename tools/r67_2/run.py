#!/usr/bin/env python3
"""R67-2: two RTL8127 requesters, one fresh PM cycle, sustained post-wake traffic."""
from pathlib import Path
import runpy
import sys

HERE = Path(__file__).resolve()
PREVIOUS = runpy.run_path(str(HERE.parents[1] / 'r67/run.py'))
SHARED = PREVIOUS['SHARED']
# Tool baseline is 40fae03 (R67 BLOCKED). base_commit remains the actual
# retained kext lineage: R66-2 binaries were built on 971198f, not R67-2.
RUN = PREVIOUS['RUN']._replace(
    number=67, token=0x672cde02, runner=HERE, dual_lucy=True,
    versions={'AMDMapperProbe': '0.74.0', 'RTL812xLucy': '1.1.241'},
    build_lucy=False, pm_boot_wake=False)
LABEL = 'R67-2'
SCOPE = 'r67-2-postwake'
IDENTITY_SCOPE = 'r67-2'
RESULT_SCOPE = 'r67-2-dual-rtl8127-postwake'
NATIVE = ('peer', 'load', 'capture', 'analyze')
POSTWAKE = ('prepare', 'sustain-peer', 'sustain', 'finish')
SETUP = ('inventory', 'inspect', 'select-next', 'adopt')


def main():
    commands = NATIVE + POSTWAKE + SETUP + ('pm', 'report')
    if len(sys.argv) < 2 or sys.argv[1] not in commands:
        print('usage: run.py {%s} [arguments]' % ','.join(commands))
        return 0 if sys.argv[1:] in (['-h'], ['--help']) else 2
    if sys.argv[1] in NATIVE:
        return SHARED['main'](RUN)
    action = sys.argv.pop(1)
    context = {'ROUND_ENTRY': globals()}
    if action in SETUP:
        return runpy.run_path(str(HERE.with_name('setup.py')), init_globals=context)['main'](action)
    if action == 'pm':
        return runpy.run_path(str(HERE.parents[1] / 'r66_2/pm.py'), init_globals=context)['main']()
    if action == 'sustain-peer':
        return runpy.run_path(str(HERE.parents[1] / 'r67/transport.py'))['peer_main'](RUN.token)
    if action == 'report':
        return runpy.run_path(str(HERE.parents[1] / 'r67/analyze.py'), init_globals=context)['main']()
    return runpy.run_path(str(HERE.parents[1] / 'r67/postwake.py'), init_globals=context)['main'](action)


if __name__ == '__main__':
    raise SystemExit(main())
