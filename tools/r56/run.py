#!/usr/bin/env python3
"""Run R56 indexed unmap with the accepted per-device clients."""
from pathlib import Path
import runpy

HERE = Path(__file__).resolve()
shared = runpy.run_path(str(HERE.parents[1] / 'r54/run.py'))
RUN = shared['common'].MixedRun(
    56, 'b339d0ec39a365b063d2d4e8774d5ebeebcd6fad',
    {'RTL812xLucy': '1.1.239', 'AMDMapperProbe': '0.63.0', 'RealtekRTL8111': '3.0.54'},
    0x56c0de56, parent='set-on-client-claim-before-pci-open', runner=HERE,
    installed_client_dependency='0.61.0')

if __name__ == '__main__':
    raise SystemExit(shared['main'](RUN))
