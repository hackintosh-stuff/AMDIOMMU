#!/usr/bin/env python3
"""R66-2: repair both-device PM participation and validate traffic after waking."""
from pathlib import Path
import runpy

HERE = Path(__file__).resolve()
R64 = runpy.run_path(str(HERE.parents[1] / 'park/run.py'))
prior = R64['RUN']
# The shared finite protocol retains numeric round 66. Use fresh r66-2 paths;
# this runner has its own token and source baseline, never reuses R66 evidence.
RUN = prior._replace(
    number=66, base_commit='971198f2f4053057b9a5740f24a75c5add0cf470',
    versions=dict(prior.versions, AMDMapperProbe='0.74.0', RealtekRTL8111='3.0.56'),
    token=0x662cde02, runner=HERE, build_lucy=False,
    installed_client_dependency=None, retained_lucy_dependency='0.70.0',
    pm_boot_wake=False, pm_lifecycle=True)

if __name__ == '__main__':
    raise SystemExit(R64['previous']['shared']['main'](RUN))
