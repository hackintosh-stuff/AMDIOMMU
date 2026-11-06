#!/usr/bin/env python3
"""After accepted R53 evidence, remove its finite job and set next boot off."""
import argparse
import json
from pathlib import Path
import plistlib
import subprocess
import sys
from common import RUN, module, project_path

D = module('_r53_disarm_deploy', 'tools/r53/deploy.py')
A = module('_r53_disarm_analysis', 'tools/r53/analyze.py')
JOB_LABEL = 'org.example.round%dload' % RUN.number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--efi', required=True)
    parser.add_argument('--capture', required=True)
    parser.add_argument('--analysis', required=True)
    args = parser.parse_args()
    saved = json.loads(project_path(args.analysis).read_text(encoding='utf-8'))
    fresh = json.loads(json.dumps(A.analyze(project_path(args.capture))))
    if fresh.get('mode') != 'auto' or not fresh.get('ok') or saved != fresh:
        raise ValueError('R%d auto analysis must pass and exactly match recomputation' % RUN.number)
    config, _, _ = D.require_efi(args.efi)
    current = D.output('nvram', 'boot-args').split(None, 1)[1].strip()
    cfg = plistlib.loads(config.read_bytes())
    if cfg['NVRAM']['Add'][D.NVRAM_GUID]['boot-args'].split() != current.split():
        raise ValueError('EFI/NVRAM boot arguments differ')
    job = Path('/Library/LaunchDaemons') / (JOB_LABEL + '.plist')
    if job.exists() and (job.resolve() != job or plistlib.loads(job.read_bytes()).get('Label') != JOB_LABEL):
        raise ValueError('unexpected finite job target')
    wanted = ' '.join([arg for arg in current.split() if not arg.startswith('amdiommu=')] + ['amdiommu=off'])
    D.run(['sudo', '-n', 'true'])
    D.run([sys.executable, D.ROOT / 'tools/dev/set-bootarg.py', config, 'amdiommu=off'])
    D.run(['sudo', '-n', 'nvram', 'boot-args=' + wanted])
    if (D.output('nvram', 'boot-args').split(None, 1)[1].strip() != wanted or
            plistlib.loads(config.read_bytes())['NVRAM']['Add'][D.NVRAM_GUID]['boot-args'] != wanted):
        raise ValueError('next-boot arguments failed read-back')
    if job.exists():
        subprocess.run(['sudo', '-n', 'launchctl', 'bootout', 'system', str(job)], check=False)
        D.run(['sudo', '-n', 'rm', '-f', job])
    if job.exists():
        raise ValueError('R%d finite daemon remains' % RUN.number)
    print('R%d accepted; next boot off; finite job removed; current domains remain active. No reboot issued.' % RUN.number)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
