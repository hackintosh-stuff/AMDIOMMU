#!/usr/bin/env python3
"""Check exact invalidation batches during both interface recovery cycles."""
from pathlib import Path
import runpy

HERE = Path(__file__).resolve()
shared = runpy.run_path(str(HERE.parents[1] / 'r54/run.py'))
RUN = shared['common'].MixedRun(
    61, '562559ac04a5d921691a0150868b6b037332b0df',
    {'RTL812xLucy': '1.1.240', 'AMDMapperProbe': '0.68.0', 'RealtekRTL8111': '3.0.54'},
    0x61c0de61, parent='set-on-client-claim-before-pci-open', runner=HERE,
    installed_client_dependency='0.61.0', abi=3, lucy_rx_pages=128, retained_lucy_dependency='0.66.0',
    reciprocal=True, exact_ranges=True)

if __name__ == '__main__':
    raise SystemExit(shared['main'](RUN))
