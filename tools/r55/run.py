#!/usr/bin/env python3
"""Use the accepted R54 clients with the R55 allocator Probe."""
from pathlib import Path
import runpy

HERE = Path(__file__).resolve()
shared = runpy.run_path(str(HERE.parents[1] / 'r54/run.py'))
RUN = shared['common'].MixedRun(
    55, '30395d3572b36457b68dca2f37e9cdb027407017',
    {'RTL812xLucy': '1.1.239', 'AMDMapperProbe': '0.62.0', 'RealtekRTL8111': '3.0.54'},
    0x55c0de55, parent='set-on-client-claim-before-pci-open', runner=HERE,
    installed_client_dependency='0.61.0')

if __name__ == '__main__':
    raise SystemExit(shared['main'](RUN))
