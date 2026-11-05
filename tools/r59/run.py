#!/usr/bin/env python3
"""Run R59 with a 128-page Lucy RX profile, ABI3 Probe, and retained RTL8111."""
from pathlib import Path
import runpy

HERE = Path(__file__).resolve()
shared = runpy.run_path(str(HERE.parents[1] / 'r54/run.py'))
RUN = shared['common'].MixedRun(
    59, '63ca1bc0ced9c82f7b460559f8cd7917cdc8c0df',
    {'RTL812xLucy': '1.1.240', 'AMDMapperProbe': '0.66.0', 'RealtekRTL8111': '3.0.54'},
    0x59c0de59, parent='set-on-client-claim-before-pci-open', runner=HERE,
    installed_client_dependency='0.61.0', abi=3, lucy_rx_pages=128, build_lucy=True)

if __name__ == '__main__':
    raise SystemExit(shared['main'](RUN))
