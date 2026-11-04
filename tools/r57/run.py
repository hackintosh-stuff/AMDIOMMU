#!/usr/bin/env python3
"""Run R57 with the accepted per-device clients and the current Probe."""
from pathlib import Path
import runpy

HERE = Path(__file__).resolve()
shared = runpy.run_path(str(HERE.parents[1] / 'r54/run.py'))
RUN = shared['common'].MixedRun(
    57, 'cc7bedff5abe77f2f2c97ab38bf223e7b3f49545',
    {'RTL812xLucy': '1.1.239', 'AMDMapperProbe': '0.64.0', 'RealtekRTL8111': '3.0.54'},
    0x57c0de57, parent='set-on-client-claim-before-pci-open', runner=HERE,
    installed_client_dependency='0.61.0')

if __name__ == '__main__':
    raise SystemExit(shared['main'](RUN))
