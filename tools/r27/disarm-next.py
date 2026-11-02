#!/usr/bin/env python3
"""Restore next-boot arm after confirmed Round29 cleanup; remove its finite job.

Run from the project: python3 -B tools/r27/disarm-next.py --efi "$EFI_MOUNT"
Does not modify the current DMA window, unload a kext, or reboot.
"""
import argparse
import importlib.util
from pathlib import Path
import plistlib
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location('round27_deployment', HERE / 'deploy.py')
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--efi', required=True, help='already mounted exact target EFI')
    args = parser.parse_args()
    props = D.output('ioreg', '-l', '-w0', '-r', '-c', 'org_example_AMDMapperProbe')
    for key, value in (('m2-3g-mode', 'all-standard'),
                       ('m2-3h-rx-state', 'drained-and-unmapped'),
                       ('m2-3b-cleanup', 'detached-after-restore-confirmed'),
                       ('m2-3e-after-exit', 'ordinary-output-resumed')):
        if not re.search(r'"' + re.escape(key) + r'"\s*=\s*"' + value + r'"', props):
            raise ValueError('Round29 exit not confirmed: ' + key)
    owners = re.search(r'"m2-3b-owners-held"\s*=\s*"?(0x[0-9a-fA-F]+|\d+)"?', props)
    if not owners or int(owners[1], 0) != 0:
        raise ValueError('a DMA owner remains or its count is absent')
    for key in ('m2-3h-rx-pending', 'm2-3h-rx-live-owners'):
        match = re.search(r'"' + re.escape(key) + r'"\s*=\s*"?(0x[0-9a-fA-F]+|\d+)"?', props)
        if not match or int(match[1], 0) != 0:
            raise ValueError('RX drain/unmap not confirmed: ' + key)
    config, _, _ = D.require_efi(args.efi)
    current = D.output('nvram', 'boot-args').split(None, 1)[1].strip()
    cfg = plistlib.loads(config.read_bytes())
    if cfg['NVRAM']['Add'][D.NVRAM_GUID]['boot-args'].split() != current.split():
        raise ValueError('current EFI and NVRAM boot-args differ')
    job = Path('/Library/LaunchDaemons/org.example.round29load.plist')
    if job.exists() and (job.resolve() != job or
                        plistlib.loads(job.read_bytes()).get('Label') != 'org.example.round29load'):
        raise ValueError('unexpected finite job target')
    wanted = ' '.join([x for x in current.split() if not x.startswith('amdiommu=')]
                      + ['amdiommu=arm'])
    D.run(['sudo', '-n', 'true'])
    D.run([sys.executable, ROOT / 'tools/r13/set-bootarg.py', config, 'amdiommu=arm'])
    D.run(['sudo', '-n', 'nvram', 'boot-args=' + wanted])
    got = D.output('nvram', 'boot-args').split(None, 1)[1].strip()
    back = plistlib.loads(config.read_bytes())['NVRAM']['Add'][D.NVRAM_GUID]['boot-args']
    if got != wanted or back != wanted:
        raise ValueError('next-boot declaration read-back differs')
    if job.exists():
        subprocess.run(['sudo', '-n', 'launchctl', 'bootout', 'system', str(job)], check=False)
        D.run(['sudo', '-n', 'rm', '-f', job])
    print('Next boot arm; Round29 finite daemon removed; current exit was confirmed. No reboot issued.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
