#!/usr/bin/env python3
"""Disarm the next boot only, after the round17 TX cleanup was confirmed.

Refuses to touch anything unless the probe itself reports that the explicit TX
domain detached AFTER the device table was restored and read back, and unless
the EFI partition and the whole disk still have the identities this project has
been using.

Round22 renamed the clean token from `detached-before-DTE-restore` to
`detached-after-restore-confirmed`: the old name described an order (detach
before restore) that this round exists to remove. Accepting only the new token
is deliberate -- an old-tokened run is exactly the one whose exit was wrong.
"""
import pathlib
import plistlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]


def main():
    props = subprocess.check_output(
        ['ioreg', '-l', '-w0', '-r', '-c', 'org_maz1_AMDMapperProbe'], text=True)
    if '"m2-3b-cleanup" = "detached-after-restore-confirmed"' not in props:
        raise ValueError('TX cleanup not confirmed; do not alter outstanding experiment')
    if '"m2-3b-owners-held" = "0x0"' not in props:
        raise ValueError('a DMA owner is still held; refusing to disarm')
    before = plistlib.loads(subprocess.check_output(['diskutil', 'info', '-plist', 'disk2s1']))
    if (before.get('DiskUUID') != '7A8D47A3-44C8-47E7-B488-A4C24DB5AC82' or
            before.get('Size') != 272629760):
        raise ValueError('partition number changed; no mount/write')
    subprocess.run(['sudo', 'diskutil', 'mount', 'disk2s1'], check=True)
    info = plistlib.loads(subprocess.check_output(['diskutil', 'info', '-plist', '/Volumes/EFI']))
    disk = plistlib.loads(subprocess.check_output(
        ['diskutil', 'info', '-plist', info['ParentWholeDisk']]))
    if (info.get('DiskUUID') != '7A8D47A3-44C8-47E7-B488-A4C24DB5AC82' or
            info.get('Size') != 272629760 or
            info.get('VolumeUUID') != '7029D646-AA46-3D16-950E-6C6AF4AB44B3' or
            info.get('MountPoint') != '/Volumes/EFI' or
            disk.get('MediaName') != 'SanDisk SD8SNAT-128G-1006' or
            disk.get('Size') != 128035676160):
        raise ValueError('wrong EFI disk; no write')
    current = subprocess.check_output(['nvram', 'boot-args'], text=True).split(None, 1)[1].strip()
    args = ' '.join([s for s in current.split() if not s.startswith('amdiommu=')]
                    + ['amdiommu=arm'])
    subprocess.run(['python3', str(ROOT / 'tools/dev/set-bootarg.py'),
                    '/Volumes/EFI/EFI/OC/config.plist', 'amdiommu=arm'], check=True)
    subprocess.run(['sudo', 'nvram', 'boot-args=' + args], check=True)
    actual = subprocess.check_output(['nvram', 'boot-args'], text=True).split(None, 1)[1].strip()
    cfg = plistlib.loads(pathlib.Path('/Volumes/EFI/EFI/OC/config.plist').read_bytes())
    if actual != args or \
            cfg['NVRAM']['Add']['7C436110-AB2A-4BBB-A880-FE41995C9F82']['boot-args'] != actual:
        raise ValueError('bootarg channels differ')
    job = pathlib.Path('/Library/LaunchDaemons/org.example.round21load.plist')
    if job.exists():
        if job.resolve() != job:
            raise ValueError('unexpected job target')
        subprocess.run(['sudo', 'launchctl', 'bootout', 'system', str(job)], check=False)
        print('Verified exact remove target: ' + str(job))
        subprocess.run(['sudo', 'rm', '-f', str(job)], check=True)
    print('Next boot arm; finite load daemon removed; NO reboot issued.')


if __name__ == '__main__':
    main()
