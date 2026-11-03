#!/usr/bin/env python3
"""Set the next boot to off after accepted Round47 capture; remove its job.

The running ordinary mapper and its persistent resources remain active.
No R31Stop, kext unload, current-domain teardown or reboot is performed.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import plistlib
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location('_r47_disarm_deploy', HERE / 'deploy.py')
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)
JOB_LABEL = 'org.example.round47load'


def require_accepted_capture(capture, analysis):
    """Recompute saved evidence before making the next-boot-only change."""
    manifest = json.loads((capture / 'manifest.json').read_text())
    if manifest.get('scope') != 'r47' or manifest.get('errors') != []:
        raise ValueError('Round47 capture is incomplete')
    saved = json.loads(analysis.read_text())
    sys.path.insert(0, str(HERE))
    spec = importlib.util.spec_from_file_location('_r47_disarm_analyze', HERE / 'analyze.py')
    analyzer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(analyzer)
    fresh = analyzer.analyze(capture)
    # Preserve the accepted Round44 fix: tuples from in-memory analysis become
    # JSON lists, so compare the same representation as the saved evidence.
    fresh = json.loads(json.dumps(fresh))
    if not fresh.get('ok') or saved != fresh:
        raise ValueError('Round47 analysis must pass and match recomputation of this capture')
    return fresh


def next_boot_args(current):
    return ' '.join([arg for arg in current.split() if not arg.startswith('amdiommu=')]
                    + ['amdiommu=off'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--efi', required=True, help='already mounted exact target EFI')
    parser.add_argument('--capture', default='runs/r47/r47-capture')
    parser.add_argument('--analysis', default='runs/r47/analysis.json')
    args = parser.parse_args()
    require_accepted_capture(D.project_path(args.capture), D.project_path(args.analysis))
    config, _, _ = D.require_efi(args.efi)
    current = D.output('nvram', 'boot-args').split(None, 1)[1].strip()
    cfg = plistlib.loads(config.read_bytes())
    if cfg['NVRAM']['Add'][D.NVRAM_GUID]['boot-args'].split() != current.split():
        raise ValueError('current EFI and NVRAM boot-args differ')
    job = Path('/Library/LaunchDaemons') / (JOB_LABEL + '.plist')
    if job.exists() and (job.resolve() != job or
                        plistlib.loads(job.read_bytes()).get('Label') != JOB_LABEL):
        raise ValueError('unexpected finite job target')
    wanted = next_boot_args(current)
    D.run(['sudo', '-n', 'true'])
    D.run([sys.executable, ROOT / 'tools/r13/set-bootarg.py', config, 'amdiommu=off'])
    D.run(['sudo', '-n', 'nvram', 'boot-args=' + wanted])
    got = D.output('nvram', 'boot-args').split(None, 1)[1].strip()
    back = plistlib.loads(config.read_bytes())['NVRAM']['Add'][D.NVRAM_GUID]['boot-args']
    if got != wanted or back != wanted:
        raise ValueError('next-boot EFI/NVRAM read-back differs')
    if job.exists():
        subprocess.run(['sudo', '-n', 'launchctl', 'bootout', 'system', str(job)], check=False)
        D.run(['sudo', '-n', 'rm', '-f', job])
    if job.exists():
        raise ValueError('Round47 finite daemon remains')
    print('Round47 capture accepted; next boot off; finite job removed. '
          'Current ordinary mapper remains active. No reboot issued.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
