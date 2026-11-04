#!/usr/bin/env python3
"""Run R58 with the accepted per-device clients and the current Probe."""
from pathlib import Path
import runpy

HERE = Path(__file__).resolve()
shared = runpy.run_path(str(HERE.parents[1] / 'r54/run.py'))
RUN = shared['common'].MixedRun(
    58, '231447265fb0d0283a5921a822a9f0760ac39d58',
    {'RTL812xLucy': '1.1.239', 'AMDMapperProbe': '0.65.0', 'RealtekRTL8111': '3.0.54'},
    0x58c0de58, parent='set-on-client-claim-before-pci-open', runner=HERE,
    installed_client_dependency='0.61.0')

if __name__ == '__main__':
    raise SystemExit(shared['main'](RUN))
