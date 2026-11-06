#!/usr/bin/env python3
"""Disarm subsequent experiment boots without rebooting or changing networking.
Run only after capture, with the existing EFI identity freshly reverified.
Current runtime DTE/cmd cleanup is separately proved by the captured probe.
"""
import argparse
import pathlib
import plistlib
import subprocess

ap = argparse.ArgumentParser()
ap.add_argument('--efi', required=True)
ap.add_argument('--efi-partition-uuid', required=True)
a = ap.parse_args()
efi = pathlib.Path(a.efi).resolve()
config = efi / 'EFI/OC/config.plist'
disk = plistlib.loads(subprocess.check_output(['diskutil', 'info', '-plist', str(efi)]))
if (disk.get('DiskUUID', '').upper() != a.efi_partition_uuid.upper() or
        disk.get('MountPoint') != str(efi) or not disk.get('Writable')):
    raise SystemExit('refuse: mounted EFI identity/writability mismatch')
root = pathlib.Path(__file__).resolve().parents[2]
guid = '7C436110-AB2A-4BBB-A880-FE41995C9F82'
# `arm` permits ordinary device attachment but does not select pgt/MMIO/DTE
# experiments. Preserve every other existing NVRAM argument exactly in order.
subprocess.run(['python3', str(root/'tools/dev/set-bootarg.py'),
                str(config), 'amdiommu=arm'], check=True)
args = plistlib.loads(config.read_bytes())['NVRAM']['Add'][guid]['boot-args']
subprocess.run(['sudo', 'nvram', 'boot-args=' + args], check=True)
got = subprocess.check_output(['nvram', 'boot-args'], text=True).split(None, 1)[1].strip()
if got != args or 'amdiommu=arm' not in args.split():
    raise SystemExit('refuse: NVRAM/OpenCore cleanup differs')
job = pathlib.Path('/Library/LaunchDaemons/org.example.round15load.plist')
if job.resolve() != job:
    raise SystemExit('refuse: unexpected resolved load-job target')
# Nonzero bootout can mean the already-completed RunAtLoad job is absent;
# deletion of its exact, task-created plist is what prevents another boot load.
p = subprocess.run(['sudo', 'launchctl', 'bootout', 'system', str(job)])
print('finite load bootout status:', p.returncode)
print('verified exact removal target:', job)
subprocess.run(['sudo', 'rm', '-f', str(job)], check=True)
print('NEXT BOOT DISARMED; no reboot, no network/MTU changes; installed kexts retained.')
