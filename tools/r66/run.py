"""R66 ordinary dual-NIC baseline; PM is armed only by tools/r66/pm.py."""
from pathlib import Path
import runpy
HERE=Path(__file__).resolve()
MODEL=runpy.run_path(str(HERE.parents[1]/'r65/model.py'))
for a in (('A','B'),('B','A')):
    for b in (('A','B'),('B','A')):
        assert MODEL['run'](a,b)
R64=runpy.run_path(str(HERE.parents[1]/'r64/run.py'))
prior=R64['RUN']
RUN=prior._replace(number=66,base_commit='f6e2ed8d1c61776e02f9b2df60abe13fb12a945a',
 versions=dict(prior.versions,AMDMapperProbe='0.73.0'),token=0x66c0de66,runner=HERE,
 build_lucy=False,pm_boot_wake=False,installed_client_dependency='0.70.0',
 retained_lucy_dependency='0.70.0')
if __name__=='__main__':
    raise SystemExit(R64['previous']['shared']['main'](RUN))
