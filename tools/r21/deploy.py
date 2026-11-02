#!/usr/bin/env python3
"""Finite round25 install. Reuses the existing EFI identity and recovery flow.

No reboot, no partitioning, no formatting, no firmware BootOrder change. The
management path is NanoKVM RNDIS en3; the selected default and test peer use en2.
"""
import argparse
import datetime
import json
import pathlib
import plistlib
import subprocess
import sys
from protocol import REQUESTS

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'r15'))
from deploy import run, sha  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
HERE = pathlib.Path(__file__).resolve().parent
BATCH = len(REQUESTS)
DRIVER_VERSION = '1.1.210'
PROBE_VERSION = '0.34.0'


MGMT_IFACE = 'en3'
MGMT_ADDR = '10.44.51.100'
TARGET_IFACE = 'en2'


def management_ready(mgmt, selected_default_route):
    # A scoped default in netstat is not the selected/global default.
    interfaces = [line.split(':', 1)[1].strip()
                  for line in selected_default_route.splitlines()
                  if line.strip().startswith('interface:')]
    return ('inet %s ' % MGMT_ADDR in mgmt and 'status: active' in mgmt
            and interfaces == [TARGET_IFACE])


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--efi', required=True)
    p.add_argument('--token', required=True, type=lambda s: int(s, 0))
    a = p.parse_args()
    if not 0 < a.token < 0x80000000:
        raise ValueError('bad token')
    efi = pathlib.Path(a.efi).resolve()
    config = efi / 'EFI/OC/config.plist'
    info = plistlib.loads(subprocess.check_output(['diskutil', 'info', '-plist', str(efi)]))
    whole = plistlib.loads(subprocess.check_output(
        ['diskutil', 'info', '-plist', info['ParentWholeDisk']]))
    if (info.get('DiskUUID', '').upper() != '7A8D47A3-44C8-47E7-B488-A4C24DB5AC82' or
            info.get('Size') != 272629760 or info.get('MountPoint') != str(efi) or
            not info.get('Writable') or whole.get('TotalSize') != 128035676160 or
            'SanDisk SD8SNAT-128G-1006' not in str(whole)):
        raise ValueError('EFI/disk identity, size or use differs; no write')
    if not config.is_file():
        raise ValueError('no OpenCore config')
    run(['sudo', '-n', 'true'])
    mgmt = subprocess.check_output(['ifconfig', MGMT_IFACE], text=True)
    selected_route = subprocess.check_output(['route', '-n', 'get', 'default'], text=True)
    if not management_ready(mgmt, selected_route):
        raise ValueError(
            'management %s (%s) or selected default %s missing; no write'
            % (MGMT_IFACE, MGMT_ADDR, TARGET_IFACE))
    bundles = [ROOT / 'build-lucy/RTL812xLucy.kext', ROOT / 'build-m1a/AMDMapperProbe.kext']
    expected = {}
    for bundle, symbol, version in zip(bundles, ['r17TxMap', 'r17Callback'],
                                       [DRIVER_VERSION, PROBE_VERSION]):
        binary = bundle / 'Contents/MacOS' / bundle.stem
        symbols = subprocess.check_output(['nm', str(binary)], text=True)
        if symbol not in symbols or 'chkstk' in symbols:
            raise ValueError('code absent/weak stack')
        if 'r16TxMap' in symbols:
            raise ValueError('bundle still carries the round-16 staging path')
        run(['codesign', '--verify', '--strict', str(bundle)])
        if plistlib.loads((bundle / 'Contents/Info.plist').read_bytes())['CFBundleVersion'] != version:
            raise ValueError('wrong version')
        expected[bundle.stem] = {
            'sha256': sha(binary),
            'uuid': subprocess.check_output(
                ['xcrun', 'dwarfdump', '--uuid', str(binary)], text=True).split()[1],
            'version': version}
    aux = pathlib.Path('/Library/KernelCollections/AuxiliaryKernelExtensions.kc')
    jobs = list(pathlib.Path('/Library/LaunchDaemons').glob('org.example.round*load.plist'))
    sources = [aux, config] + [pathlib.Path('/Library/Extensions') / b.name for b in bundles] + jobs
    total = sum(f.stat().st_size for s in sources
                for f in (s.rglob('*') if s.is_dir() else [s]) if f.is_file())
    if total > 1024 ** 3:
        raise ValueError('backup >1GiB requires separate permission')
    backup = pathlib.Path.home() / (
        'r25-recovery-' + datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ'))
    backup.mkdir()
    print('Recovery copy %d bytes -> %s' % (total, backup), flush=True)
    for s in sources:
        run(['sudo', 'cp', '-Rp', str(s), str(backup / s.name)])
    old = subprocess.check_output(['nvram', 'boot-args'], text=True)
    (backup / 'boot-args.txt').write_text(old)
    for b in bundles:
        target = pathlib.Path('/Library/Extensions') / b.name
        if target.resolve() != target or target.parent != pathlib.Path('/Library/Extensions'):
            raise ValueError('unexpected install target')
        print('Verified replacement target: ' + str(target), flush=True)
        run(['sudo', 'rm', '-rf', str(target)])
        run(['sudo', 'cp', '-R', str(b), str(target)])
        run(['sudo', 'chown', '-R', 'root:wheel', str(target)])
        run(['sudo', 'chmod', '-R', 'go-w', str(target)])
        if sha(target / 'Contents/MacOS' / b.stem) != expected[b.stem]['sha256']:
            raise ValueError('installed bytes differ')
    run(['sudo', 'kmutil', 'create', '-n', 'aux', '-R', '/',
         '-B', '/System/Library/KernelCollections/BootKernelExtensions.kc',
         '-S', '/System/Library/KernelCollections/SystemKernelExtensions.kc',
         '-A', str(aux), '-r', '/Library/Extensions', '--allow-missing-kdk', '-z', '-v'])
    inspected = run(['sudo', 'kmutil', 'inspect', '-A', str(aux), '--show-kext-uuids'],
                    capture=True)
    if not all(v['uuid'].lower() in inspected.lower() for v in expected.values()):
        raise ValueError('new UUID absent')
    tokenarg = 'amdiommu=pgt.batch%d.t0x%08x.std' % (BATCH, a.token)
    args = old.split(None, 1)[1].strip().split()
    bootargs = ' '.join([x for x in args if not x.startswith('amdiommu=')] + [tokenarg])
    run(['python3', str(ROOT / 'tools/r13/set-bootarg.py'), str(config), tokenarg])
    run(['sudo', 'nvram', 'boot-args=' + bootargs])
    cfg = plistlib.loads(config.read_bytes())
    if cfg['NVRAM']['Add']['7C436110-AB2A-4BBB-A880-FE41995C9F82']['boot-args'] != bootargs:
        raise ValueError('EFI/NVRAM differ')
    out = pathlib.Path.home() / 'r21load'
    out.mkdir(exist_ok=True)
    (out / 'token.txt').write_text('0x%08x\n' % a.token)
    (out / 'batch.txt').write_text('%d\n' % BATCH)
    (out / 'expected-version.json').write_text(json.dumps(expected, indent=2) + '\n')
    for job in jobs:
        subprocess.run(['sudo', 'launchctl', 'bootout', 'system', str(job)], check=False)
        if job.resolve().parent != pathlib.Path('/Library/LaunchDaemons'):
            raise ValueError('wrong job path')
        run(['sudo', 'rm', '-f', str(job)])
    target = '/Library/LaunchDaemons/org.example.round21load.plist'
    run(['sudo', 'cp', str(ROOT / 'tools/r21/load-daemon.plist'), target])
    run(['sudo', 'chown', 'root:wheel', target])
    run(['sudo', 'chmod', '644', target])
    # Round21: check the things that made previous runs ambiguous BEFORE the
    # reboot, not after. A plist whose Label/paths still point at another round,
    # a load dir the user cannot write, or a peer whose UDP port is closed all
    # produce `acked=0`, which in the artifact is indistinguishable from a
    # translation fault. Deploying on top of those wastes the run.
    pre = subprocess.run([sys.executable, str(HERE / 'preflight.py')],
                         capture_output=True, text=True)
    print(pre.stdout.rstrip())
    if pre.returncode != 0:
        # Two checks are legitimately red before the reboot:
        #   * peer        -- started separately, and the run needs it listening;
        #   * kexts-loaded-- the new bytes are on disk but the OLD kexts are
        #                    still in memory until the machine restarts.
        # Everything else must be green. Capture does not tolerate either one.
        blockers = [l for l in pre.stdout.splitlines()
                    if l.strip().startswith('FAIL') and 'peer' not in l
                    and 'kexts-loaded' not in l]
        if blockers:
            print('\nDEPLOY BLOCKED: fix the failures above, then re-run deploy.',
                  flush=True)
            raise SystemExit(3)
        print('\nDEPLOY READY (peer check still red: start the peer and open the '
              'firewall before rebooting, or the run will report acked=0).',
              flush=True)
    else:
        print('DEPLOY READY; no reboot issued', flush=True)


if __name__ == '__main__':
    main()
