#!/usr/bin/env python3
"""Revoke and restore A's requester permissions without stopping B's DMA."""
from pathlib import Path
import runpy

HERE = Path(__file__).resolve()
shared = runpy.run_path(str(HERE.parents[1] / 'r54/run.py'))
RUN = shared['common'].MixedRun(
    63, '4309a75855f67957284ec71909378b72fa132a05',
    {'RTL812xLucy': '1.1.240', 'AMDMapperProbe': '0.70.0', 'RealtekRTL8111': '3.0.55'},
    0x63c0de63, parent='set-on-client-claim-before-pci-open', runner=HERE,
    installed_client_dependency=None, abi=3, lucy_rx_pages=128, retained_lucy_dependency='0.66.0',
    reciprocal=True, exact_ranges=True, cached_ring_head=True, requester_access=True)

if __name__ == '__main__':
    raise SystemExit(shared['main'](RUN))
