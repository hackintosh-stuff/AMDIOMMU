#!/usr/bin/env python3
"""One necessary round15 deployment identity check; no historical test/audit.
Run ON THE MAC from the project. Requires an already verified/mounted EFI.
Makes only a bounded recovery copy (<1GiB or refuses), installs two kexts,
updates existing OpenCore/NVRAM amdiommu value, and stages finite boot load.
Does not reboot, repartition, format, or create a firmware boot entry.
"""
import argparse
import datetime
import hashlib
import pathlib
import plistlib
import re
import shutil
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]

def run(args, capture=False):
    print('+ ' + ' '.join(str(a) for a in args), flush=True)
    p = subprocess.run([str(a) for a in args], check=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None, text=True)
    if capture:
        print(p.stdout, end='', flush=True)
        return p.stdout

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--efi', required=True)
    ap.add_argument('--efi-partition-uuid', required=True)
    ap.add_argument('--token', required=True, type=lambda s: int(s, 0))
    a = ap.parse_args()
    if not 0 < a.token < 0x80000000:
        raise ValueError('token must be a nonzero low-half 32bit value')
    efi = pathlib.Path(a.efi).resolve()
    config = efi / 'EFI/OC/config.plist'
    if not config.is_file():
        raise ValueError('mount verified OpenCore EFI first')
    disk = plistlib.loads(subprocess.check_output(['diskutil', 'info', '-plist', str(efi)]))
    if disk.get('DiskUUID', '').upper() != a.efi_partition_uuid.upper():
        raise ValueError('mounted EFI partition GUID does not match operator verification')
    if disk.get('MountPoint') != str(efi) or not disk.get('Writable'):
        raise ValueError('EFI not mounted writable')
    run(['sudo', '-n', 'true'])
    run(['netstat', '-rn', '-f', 'inet'])
    # Management en0 must still own its address and a default route of its own;
    # the same-subnet en2 global route is not proof that management was lost.
    en0 = subprocess.check_output(['ifconfig', 'en0'], text=True)
    routes = subprocess.check_output(['netstat', '-rn', '-f', 'inet'], text=True)
    if 'inet 192.168.50.204 ' not in en0 or not any(
            ln.startswith('default') and 'en0' in ln for ln in routes.splitlines()):
        raise ValueError('management en0 address/default route not intact')
    driver = ROOT / 'build-lucy/RTL812xLucy.kext'
    probe = ROOT / 'build-m1a/AMDMapperProbe.kext'
    for bundle, executable, symbol in [(driver, 'RTL812xLucy', 'r15PoolControl'),
                                      (probe, 'AMDMapperProbe', 'm2b2R15PrepareMap')]:
        binary = bundle / 'Contents/MacOS' / executable
        nm = subprocess.check_output(['nm', str(binary)], text=True)
        if symbol not in nm or 'chkstk' in nm:
            raise ValueError('new code missing or oversized kernel stack')
        run(['codesign', '--verify', '--strict', str(bundle)])
    with (probe / 'Contents/Info.plist').open('rb') as f:
        if plistlib.load(f)['CFBundleVersion'] != '0.25.1':
            raise ValueError('wrong round15 probe version')
    aux = pathlib.Path('/Library/KernelCollections/AuxiliaryKernelExtensions.kc')
    recovery_sources = [aux, config,
        pathlib.Path('/Library/Extensions/RTL812xLucy.kext'),
        pathlib.Path('/Library/Extensions/AMDMapperProbe.kext')]
    jobs = list(pathlib.Path('/Library/LaunchDaemons').glob('org.example.round*load.plist'))
    recovery_sources += jobs
    total = sum(p.stat().st_size for src in recovery_sources
        for p in (list(src.rglob('*')) if src.is_dir() else [src]) if p.is_file())
    if total > 1024**3:
        raise ValueError('recovery copy would exceed1GiB; separate permission required')
    stamp = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    recovery = pathlib.Path.home() / ('r15-recovery-' + stamp)
    recovery.mkdir(exist_ok=False)
    print('Recovery copy: %d bytes -> %s' % (total, recovery), flush=True)
    for src in recovery_sources:
        run(['sudo', 'cp', '-Rp', str(src), str(recovery / src.name)])
    old_args = subprocess.check_output(['nvram', 'boot-args'], text=True)
    (recovery / 'boot-args.txt').write_text(old_args)
    expected = {}
    for bundle in [driver, probe]:
        target = pathlib.Path('/Library/Extensions') / bundle.name
        if target.resolve() != target or target.parent != pathlib.Path('/Library/Extensions'):
            raise ValueError('unexpected resolved install deletion target: ' + str(target))
        print('Verified exact replacement target: ' + str(target), flush=True)
        run(['sudo', 'rm', '-rf', str(target)])
        run(['sudo', 'cp', '-R', str(bundle), str(target)])
        run(['sudo', 'chown', '-R', 'root:wheel', str(target)])
        run(['sudo', 'chmod', '-R', 'go-w', str(target)])
        executable = 'RTL812xLucy' if bundle == driver else 'AMDMapperProbe'
        built = bundle / 'Contents/MacOS' / executable
        installed = target / 'Contents/MacOS' / executable
        if sha(built) != sha(installed):
            raise ValueError('installed binary differs')
        identity = subprocess.check_output(['xcrun', 'dwarfdump', '--uuid', str(installed)], text=True)
        expected[executable] = {'sha256': sha(installed), 'uuid': identity.split()[1],
            'version': plistlib.loads((target/'Contents/Info.plist').read_bytes())['CFBundleVersion']}
    run(['sudo', 'kmutil', 'create', '-n', 'aux', '-R', '/', '-B',
        '/System/Library/KernelCollections/BootKernelExtensions.kc', '-S',
        '/System/Library/KernelCollections/SystemKernelExtensions.kc', '-A',
        str(aux), '-r', '/Library/Extensions', '--allow-missing-kdk', '-z', '-v'])
    inspect = run(['sudo', 'kmutil', 'inspect', '-A', str(aux),
                   '--show-kext-uuids'], capture=True)
    for name, item in expected.items():
        if item['uuid'].lower() not in inspect.lower():
            raise ValueError('new bundle UUID missing from rebuilt AuxKC: ' + name)
    token_arg = 'amdiommu=pgt.batch4.t0x%08x' % a.token
    args = old_args.split(None, 1)[1].strip().split()
    new_args = ' '.join([x for x in args if not x.startswith('amdiommu=')] + [token_arg])
    run(['python3', str(ROOT/'tools/dev/set-bootarg.py'), str(config), token_arg])
    run(['sudo', 'nvram', 'boot-args=' + new_args])
    actual = subprocess.check_output(['nvram', 'boot-args'], text=True).split(None, 1)[1].strip()
    cfg = plistlib.loads(config.read_bytes())
    guid = '7C436110-AB2A-4BBB-A880-FE41995C9F82'
    efi_args = cfg['NVRAM']['Add'][guid]['boot-args']
    if actual != efi_args or token_arg not in actual.split():
        raise ValueError('NVRAM/OpenCore boot argument channels differ')
    load = pathlib.Path.home() / 'r15load'
    load.mkdir(exist_ok=True)
    (load/'token.txt').write_text('0x%08x\n' % a.token)
    (load/'batch.txt').write_text('4\n')
    import json
    (load/'expected-version.json').write_text(json.dumps(expected, indent=2)+'\n')
    for job in jobs:
        # Exact current paths have been enumerated and backed up; disable only
        # experiment load jobs, never user/OS launchd services.
        subprocess.run(['sudo', 'launchctl', 'bootout', 'system', str(job)], check=False)
        if job.resolve().parent != pathlib.Path('/Library/LaunchDaemons'):
            raise ValueError('unexpected job removal path')
        run(['sudo', 'rm', '-f', str(job)])
    run(['sudo', 'cp', str(ROOT/'tools/r15/load-daemon.plist'),
         '/Library/LaunchDaemons/org.example.round15load.plist'])
    run(['sudo', 'chown', 'root:wheel', '/Library/LaunchDaemons/org.example.round15load.plist'])
    run(['sudo', 'chmod', '644', '/Library/LaunchDaemons/org.example.round15load.plist'])
    print('DEPLOY READY; reboot only after peer and NanoKVM are verified.', flush=True)
    print('Recovery: ' + str(recovery), flush=True)

if __name__ == '__main__':
    main()
