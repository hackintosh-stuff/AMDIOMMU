#!/usr/bin/env python3
"""R65: validate coordinated PM ordering and preserve the R64 dual-NIC workload."""
from pathlib import Path
import runpy
HERE=Path(__file__).resolve()
MODEL=runpy.run_path(str(HERE.with_name('model.py')))
for a in (('A','B'),('B','A')):
    for b in (('A','B'),('B','A')):
        assert MODEL['run'](a,b)
R64=runpy.run_path(str(HERE.parents[1]/'r64/run.py'))
RUN=R64['RUN']._replace(number=65,base_commit='8cfd4aca2ae8a7af1635e21583047d1b01e677ec',versions=dict(R64['RUN'].versions,AMDMapperProbe='0.71.0'),token=0x65c0de65,runner=HERE,build_lucy=False,installed_client_dependency='0.70.0',retained_lucy_dependency='0.70.0')
if __name__ == '__main__':
    raise SystemExit(R64['previous']['shared']['main'](RUN))
