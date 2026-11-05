#!/usr/bin/env python3
"""Exercise both interface lifecycles with the retained mixed clients and ABI3 Probe."""
from pathlib import Path
import runpy

HERE = Path(__file__).resolve()
shared = runpy.run_path(str(HERE.parents[1] / 'r54/run.py'))
RUN = shared['common'].MixedRun(
    60, 'db18ba4b0e3f648980339ee182ad2d27be2205d5',
    {'RTL812xLucy': '1.1.240', 'AMDMapperProbe': '0.67.0', 'RealtekRTL8111': '3.0.54'},
    0x60c0de60, parent='set-on-client-claim-before-pci-open', runner=HERE,
    installed_client_dependency='0.61.0', abi=3, lucy_rx_pages=128, retained_lucy_dependency='0.66.0',
    reciprocal=True)

if __name__ == '__main__':
    raise SystemExit(shared['main'](RUN))
