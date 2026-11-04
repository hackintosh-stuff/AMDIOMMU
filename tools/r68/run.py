"""R68: restore the R64 ordinary dual-requester lifecycle; system PM stays deferred."""
from pathlib import Path
import runpy
HERE=Path(__file__).resolve()
R64=runpy.run_path(str(HERE.parents[1]/'r64/run.py'))
prior=R64['RUN']
RUN=prior._replace(number=68,base_commit='a7d09010133560fd5f6a2779a3c45a4321a25994',
 versions=dict(prior.versions,AMDMapperProbe='0.72.0'),token=0x68c0de68,runner=HERE,
 build_lucy=False,pm_boot_wake=False,installed_client_dependency='0.70.0',
 retained_lucy_dependency='0.70.0')
if __name__=='__main__':
    raise SystemExit(R64['previous']['shared']['main'](RUN))
