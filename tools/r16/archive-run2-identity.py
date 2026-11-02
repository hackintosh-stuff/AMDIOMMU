#!/usr/bin/env python3
"""Run2 bounded source/binary capture; run ONLY after parent's evidence capture.
No rebuild/deployment/restart. --plan still invokes compiler -M (preprocess only).
Loaded UUID arguments must come from actual run2 capture, not expected build IDs.
"""
import argparse
from pathlib import Path
import subprocess
import sys
import uuid
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--out',required=True);p.add_argument('--plan',action='store_true')
p.add_argument('--driver-uuid',required=True);p.add_argument('--probe-uuid',required=True)
p.add_argument('--load-root',default='/Users/ling/r16load')
p.add_argument('--extra-file',action='append',default=[])
a=p.parse_args()
# Syntax validation is local; build/capture equality is written in binary-identity.json.
for s in (a.driver_uuid,a.probe_uuid):uuid.UUID(s)
cmd=[sys.executable,str(Path(__file__).with_name('archive-run1-identity.py')),
 '--out',a.out,'--driver-root','/Users/ling/r16-driver-staging-agent',
 '--probe-root','/Users/ling/r12work','--driver-log','build-driver-staging.log',
 '--load-root',a.load_root,'--run-label','Run2 page-aligned real TX staging 1.1.201',
 '--driver-uuid',a.driver_uuid,'--probe-uuid',a.probe_uuid,
 '--extra-file',str(Path(__file__).resolve())]
if a.plan:cmd.append('--plan')
for name in a.extra_file:cmd.extend(['--extra-file',name])
subprocess.run(cmd,check=True)
