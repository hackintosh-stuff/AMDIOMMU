"""R64: both mixed-driver requesters independently park and restore DMA access."""
from pathlib import Path
import runpy
HERE=Path(__file__).resolve()
previous=runpy.run_path(str(HERE.parents[1]/'perms/run.py')); prior=previous['RUN']
RUN=prior._replace(number=64,base_commit='e0f5ef93f8a665c9597c3989a9c8e92a34a9709d',
 versions=dict(prior.versions,RTL812xLucy='1.1.241'),token=0x64c0de64,runner=HERE,
 build_lucy=True,retained_lucy_dependency=None,lucy_rx_pages=128,abi=3,both_requester_access=True)
if __name__=='__main__': raise SystemExit(previous['shared']['main'](RUN))
