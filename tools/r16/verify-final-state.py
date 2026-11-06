#!/usr/bin/env python3
"""Read-only verification after finite-run disarm; never mount/write/reboot."""
import json
import pathlib
import plistlib
import subprocess


def run(*args):
    return subprocess.check_output(list(args), text=True)


def main():
    info = plistlib.loads(subprocess.check_output(['diskutil', 'info', '-plist', '/Volumes/EFI']))
    disk = plistlib.loads(subprocess.check_output(['diskutil', 'info', '-plist', info['ParentWholeDisk']]))
    assert info['DiskUUID'] == '7A8D47A3-44C8-47E7-B488-A4C24DB5AC82'
    assert info['VolumeUUID'] == '7029D646-AA46-3D16-950E-6C6AF4AB44B3'
    assert info['MountPoint'] == '/Volumes/EFI' and info['Size'] == 272629760
    assert disk['MediaName'] == 'SanDisk SD8SNAT-128G-1006' and disk['Size'] == 128035676160
    config = plistlib.loads(pathlib.Path('/Volumes/EFI/EFI/OC/config.plist').read_bytes())
    oc = config['NVRAM']['Add']['7C436110-AB2A-4BBB-A880-FE41995C9F82']['boot-args']
    nvram = run('nvram', 'boot-args').split(None, 1)[1].strip()
    assert nvram == oc
    assert [v for v in nvram.split() if v.startswith('amdiommu=')] == ['amdiommu=arm']
    daemon = pathlib.Path('/Library/LaunchDaemons/org.example.round16load.plist')
    assert not daemon.exists()
    job = subprocess.run(['launchctl', 'print', 'system/org.example.round16load'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    assert job.returncode != 0 and 'Could not find service' in job.stdout, job.stdout
    props = run('ioreg', '-l', '-w0', '-r', '-c', 'org_maz1_AMDMapperProbe')
    assert '"m2-3a-cleanup" = "detached-before-DTE-restore"' in props
    result = {
        'status': 'PASS',
        'operation': 'read-only post-run verification; no mount/write/reboot',
        'host': run('hostname').strip(),
        'partition': {k: info.get(k) for k in ('DeviceIdentifier', 'DiskUUID', 'VolumeUUID', 'MountPoint', 'Size')},
        'disk': {k: disk.get(k) for k in ('DeviceIdentifier', 'MediaName', 'Size')},
        'oc_boot_args': oc,
        'nvram_boot_args': nvram,
        'daemon_file_exists': daemon.exists(),
        'launchctl_query': {'returncode': job.returncode, 'output': job.stdout},
        'cleanup': 'detached-before-DTE-restore',
        'default_route': run('route', '-n', 'get', 'default'),
        'peer_route': run('route', '-n', 'get', '192.168.50.122'),
        'management_en0': run('ifconfig', 'en0'),
        'target_en2': run('ifconfig', 'en2'),
    }
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
