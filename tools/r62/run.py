#!/usr/bin/env python3
"""Exercise the shared command-ring HEAD cache across both interface recovery cycles."""
from pathlib import Path
import runpy

HERE = Path(__file__).resolve()
shared = runpy.run_path(str(HERE.parents[1] / 'r54/run.py'))
RUN = shared['common'].MixedRun(
    62, 'e4d61d84ae08e38ab79dce8330cc4f6aaca0b7fe',
    {'RTL812xLucy': '1.1.240', 'AMDMapperProbe': '0.69.0', 'RealtekRTL8111': '3.0.54'},
    0x62c0de62, parent='set-on-client-claim-before-pci-open', runner=HERE,
    installed_client_dependency='0.61.0', abi=3, lucy_rx_pages=128, retained_lucy_dependency='0.66.0',
    reciprocal=True, exact_ranges=True, cached_ring_head=True)

if __name__ == '__main__':
    raise SystemExit(shared['main'](RUN))
