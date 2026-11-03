#!/usr/bin/env python3
"""Round43 install, with exact disk checks and a recovery copy under 1 GiB.

Run from the project on the Mac. --check-only performs the same read-only
prechecks and prints the plan. Neither path reboots or changes network settings.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import plistlib
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
ROUND = 43
BATCH = 512
DEFAULT_TOKEN = None
DEFAULT_PORT = 9110
TSO4, TSO6 = False, False
ENTRY_POINTS = ('boot-load.sh', 'load.py', 'protocol.py')
REQUIRED_SYMBOLS = ('r17TxMap', 'r17Callback')
# Accepted R42 initial RX IOVA; stop NIC before DTE and use an IOVA-only domain.
BASE_COMMIT = '7af436acaad62a58acbdb4b788142145ec4c744f'
UPSTREAM_COMMIT = '639144d1f284a9fee222a518691b01494f5e265d'
DRIVER_VERSION = '1.1.228'
PROBE_VERSION = '0.52.0'
EFI_UUID = '7A8D47A3-44C8-47E7-B488-A4C24DB5AC82'
EFI_VOLUME_UUID = '7029D646-AA46-3D16-950E-6C6AF4AB44B3'
EFI_SIZE = 272629760
WHOLE_SIZE = 128035676160
WHOLE_MODEL = 'SanDisk SD8SNAT-128G-1006'
NVRAM_GUID = '7C436110-AB2A-4BBB-A880-FE41995C9F82'
MGMT_IFACE, MGMT_ADDR, TARGET_IFACE = 'en3', '10.44.51.100', 'en2'


def run(args, capture=False):
    print('+ ' + ' '.join(str(arg) for arg in args), flush=True)
    proc = subprocess.run([str(arg) for arg in args], cwd=str(ROOT), check=True,
                          text=True, stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.STDOUT if capture else None)
    if capture:
        print(proc.stdout, end='', flush=True)
        return proc.stdout


def output(*args):
    return subprocess.check_output(args, cwd=str(ROOT), text=True)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def project_path(value):
    path = Path(value)
    if path.is_absolute():
        raise ValueError('workspace paths must be relative to the project: ' + value)
    path = (ROOT / path).resolve()
    path.relative_to(ROOT)
    return path


def route_iface(text):
    return [line.split(':', 1)[1].strip() for line in text.splitlines()
            if line.strip().startswith('interface:')]


def management_ready(mgmt, selected_default_route):
    return ('inet %s ' % MGMT_ADDR in mgmt and 'status: active' in mgmt and
            route_iface(selected_default_route) == [TARGET_IFACE])


def require_tso_off(info):
    personalities = info.get('IOKitPersonalities', {})
    params = personalities.get('RTL8125', {}).get('Driver Parameters', {})
    if any(params.get(key) is not False for key in ('enableTSO4', 'enableTSO6')):
        raise ValueError('mapped DMA requires final Driver Parameters '
                         'enableTSO4=false and enableTSO6=false; no automatic change')


def require_efi(efi):
    """Check the exact mounted EFI; return (config_path, partition_info, disk_info)."""
    efi = Path(efi).expanduser().resolve()
    info = plistlib.loads(subprocess.check_output(['diskutil', 'info', '-plist', str(efi)]))
    whole = plistlib.loads(subprocess.check_output(
        ['diskutil', 'info', '-plist', info['ParentWholeDisk']]))
    if (info.get('DiskUUID', '').upper() != EFI_UUID or
            info.get('VolumeUUID', '').upper() != EFI_VOLUME_UUID or
            info.get('Size') != EFI_SIZE or info.get('MountPoint') != str(efi) or
            not info.get('Writable') or whole.get('TotalSize') != WHOLE_SIZE or
            whole.get('MediaName') != WHOLE_MODEL):
        raise ValueError('exact EFI/disk UUID, size, mount or model differs; no write')
    config = efi / 'EFI/OC/config.plist'
    if not config.is_file():
        raise ValueError('exact mounted EFI has no OpenCore config.plist')
    return config, info, whole


def require_target_ready(text):
    if ('status: active' not in text or not re.search(r'\binet\s+\S+', text) or
            not re.search(r'\bmtu\s+1500\b', text)):
        raise ValueError('en2 must already be active with IPv4 and MTU 1500')


def bundle_identity(bundle, version, symbol):
    info = plistlib.loads((bundle / 'Contents/Info.plist').read_bytes())
    if info.get('CFBundleVersion') != version:
        raise ValueError('wrong bundle version: ' + str(bundle))
    if bundle.stem == 'RTL812xLucy':
        require_tso_off(info)
    binary = bundle / 'Contents/MacOS' / bundle.stem
    symbols = output('nm', str(binary))
    if symbol not in symbols or 'chkstk' in symbols or 'r16TxMap' in symbols:
        raise ValueError('required code absent or obsolete/weak-stack path present')
    run(['codesign', '--verify', '--strict', bundle])
    identity = output('xcrun', 'dwarfdump', '--uuid', str(binary))
    matches = re.findall(r'UUID:\s*([0-9A-Fa-f-]+)\s*\(x86_64\)', identity)
    if len(matches) != 1:
        raise ValueError('expected one x86_64 Mach-O UUID: ' + str(binary))
    return {'sha256': sha(binary), 'uuid': matches[0], 'version': version}


def source_identity():
    """Deploy a committed successor of the recorded source baseline."""
    commit = output('git', 'rev-parse', 'HEAD').strip()
    if not re.fullmatch(r'[0-9a-f]{40}', commit) or commit == BASE_COMMIT:
        raise ValueError('commit the applied and software-tested Round%d source before deployment' % ROUND)
    subprocess.run(['git', 'merge-base', '--is-ancestor', BASE_COMMIT, commit],
                   cwd=str(ROOT), check=True)
    dirty = output('git', 'status', '--porcelain=v1', '--untracked-files=normal',
                   '--', 'kext', 'tools', 'include', 'src', 'tests', 'fixtures', 'reference')
    if dirty.strip():
        raise ValueError('uncommitted source differs from the deployment commit: ' + dirty.strip())
    return {'repository': 'repos/AMDIOMMU', 'base_commit': BASE_COMMIT,
            'commit': commit, 'upstream_commit': UPSTREAM_COMMIT,
            'source_snapshots_in_evidence': False}


def daemon_plist(out, peer, port):
    return {
        'Label': 'org.example.round%dload' % ROUND,
        'ProgramArguments': ['/bin/sh', str(HERE / 'boot-load.sh'),
                             out.relative_to(ROOT).as_posix()],
        'WorkingDirectory': str(ROOT),
        'EnvironmentVariables': {
            'PYTHON': str(Path(sys.executable).resolve()), 'IFACE': TARGET_IFACE,
            'PEER': peer, 'PORT': str(port),
            'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'},
        'RunAtLoad': True, 'KeepAlive': False,
        'StandardOutPath': str(out / 'launchd.out'),
        'StandardErrorPath': str(out / 'launchd.err')}


def kernel_bootarg(token):
    return 'amdiommu=pgt.batch%d.t0x%08x.std.alltx.rxstd.session' % (BATCH, token)


def round_plan():
    """Historical R43 defaults; later entry points replace this declaration."""
    return {'round': 43, 'driver_mode': 2, 'scope': 'IOVA-only-domain-native-RX1024-batch16',
            'kernel_batch': BATCH, 'application_requests': 8192, 'rx_slots': 1024,
            'rx_lifetime': 'driver-owned-streaming', 'rx_batch_max': 16, 'rx_replacement': 'normal-mbuf',
            'physical_mapping': 'iova-only', 'fixed_dma_iova': True, 'active_identity_pages': 0, 'nic_stop_before_dte': True, 'final_leaf_pages': 0, 'rx_source': 'lucy-normal-ring', 'experimental_pool': False, 'experimental_spares': 0,
            'session_mode': 'explicit-stop', 'idle_seconds': 125,
            'stop_mode': 'local-nic-reset', 'peer_tail_required': False,
            'domain_lifetime': 'service-owned', 'setup_worker_returns': True,
            'tx_iova_pages': 256, 'tx_live_records': 16, 'tx_max_mapping_pages': 32,
            'capacity_probe_maps': 9, 'capacity_probe_peak_owners': 8}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--efi', required=True, help='already mounted exact target EFI')
    parser.add_argument('--token', required=DEFAULT_TOKEN is None, default=DEFAULT_TOKEN,
                        type=lambda value: int(value, 0))
    parser.add_argument('--out', default='runs/r%d' % ROUND)
    parser.add_argument('--backup', help='project-relative recovery directory')
    parser.add_argument('--peer', default='192.168.50.122')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT)
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    if not 0 < args.token < 0x80000000 or not 0 < args.port <= 65535:
        raise ValueError('invalid token or port')
    source_ref = source_identity()
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out = project_path(args.out)
    backup = project_path(args.backup or ('runs/recovery-r%d-' % ROUND + stamp))
    if backup.exists() or backup == out:
        raise ValueError('recovery directory must be new and separate from load output')
    if any((out / name).exists() for name in ('load.txt', 'client.log')):
        raise ValueError('load output already contains a run; choose a fresh --out')
    efi = Path(args.efi).expanduser().resolve()
    config, _, _ = require_efi(efi)
    cfg = plistlib.loads(config.read_bytes())
    old = output('nvram', 'boot-args')
    current_args = old.split(None, 1)[1].strip()
    config_args = cfg['NVRAM']['Add'][NVRAM_GUID]['boot-args']
    if current_args.split() != config_args.split():
        raise ValueError('current EFI and NVRAM boot-args differ; no write')
    if not management_ready(output('ifconfig', MGMT_IFACE),
                            output('route', '-n', 'get', 'default')):
        raise ValueError('RNDIS en3 10.44.51.100 or selected default en2 missing')
    require_target_ready(output('ifconfig', TARGET_IFACE))
    if route_iface(output('route', '-n', 'get', args.peer)) != [TARGET_IFACE]:
        raise ValueError('peer route must already use en2')
    for name in ENTRY_POINTS:
        if not (HERE / name).is_file():
            raise ValueError('missing Round%d entry point: %s' % (ROUND, name))
    bundles = [ROOT / 'build-lucy/RTL812xLucy.kext', ROOT / 'build-m1a/AMDMapperProbe.kext']
    expected = {}
    for bundle, version, symbol in zip(bundles, (DRIVER_VERSION, PROBE_VERSION),
                                       REQUIRED_SYMBOLS):
        expected[bundle.stem] = bundle_identity(bundle, version, symbol)
    aux = Path('/Library/KernelCollections/AuxiliaryKernelExtensions.kc')
    jobs = sorted(Path('/Library/LaunchDaemons').glob('org.example.round*load.plist'))
    targets = [Path('/Library/Extensions') / bundle.name for bundle in bundles]
    for path in targets + jobs:
        if path.resolve() != path:
            raise ValueError('unexpected symlink in system replacement target: ' + str(path))
    sources = [aux, config] + targets + jobs
    if not all(source.exists() for source in sources):
        raise ValueError('a required recovery source is missing')
    total = sum(path.stat().st_size for source in sources
                for path in (source.rglob('*') if source.is_dir() else [source])
                if path.is_file()) + len(old.encode('utf-8'))
    if total >= 1024 ** 3:
        raise ValueError('recovery copy must remain below 1 GiB')
    tokenarg = kernel_bootarg(args.token)
    bootargs = ' '.join([arg for arg in current_args.split()
                         if not arg.startswith('amdiommu=')] + [tokenarg])
    plan = round_plan()
    plan.update({'source_commit': source_ref['commit'], 'base_commit': BASE_COMMIT,
            'bootarg': tokenarg, 'mtu': 1500, 'tso4': TSO4, 'tso6': TSO6,
            'out': out.relative_to(ROOT).as_posix(),
            'backup': backup.relative_to(ROOT).as_posix(),
            'recovery_bytes': total, 'expected': expected})
    print(json.dumps(plan, indent=2), flush=True)
    if args.check_only:
        return 0
    run(['sudo', '-n', 'true'])
    backup.mkdir(parents=True, exist_ok=False)
    for source in sources:
        run(['sudo', 'cp', '-Rp', source, backup / source.name])
    (backup / 'boot-args.txt').write_text(old, encoding='utf-8')
    out.mkdir(parents=True, exist_ok=True)
    for bundle, target, symbol in zip(bundles, targets, REQUIRED_SYMBOLS):
        print('Verified replacement target: ' + str(target), flush=True)
        run(['sudo', 'rm', '-rf', target])
        run(['sudo', 'cp', '-R', bundle, target])
        run(['sudo', 'chown', '-R', 'root:wheel', target])
        run(['sudo', 'chmod', '-R', 'go-w', target])
        got = bundle_identity(target, expected[bundle.stem]['version'], symbol)
        if got != expected[bundle.stem]:
            raise ValueError('installed bundle identity differs from build')
    run(['sudo', 'kmutil', 'create', '-n', 'aux', '-R', '/',
         '-B', '/System/Library/KernelCollections/BootKernelExtensions.kc',
         '-S', '/System/Library/KernelCollections/SystemKernelExtensions.kc',
         '-A', aux, '-r', '/Library/Extensions', '--allow-missing-kdk', '-z', '-v'])
    inspected = run(['sudo', 'kmutil', 'inspect', '-A', aux, '--show-kext-uuids'], capture=True)
    if not all(item['uuid'].lower() in inspected.lower() for item in expected.values()):
        raise ValueError('new UUID absent from rebuilt Auxiliary KC')
    run([sys.executable, ROOT / 'tools/r13/set-bootarg.py', config, tokenarg])
    run(['sudo', 'nvram', 'boot-args=' + bootargs])
    actual_args = output('nvram', 'boot-args').split(None, 1)[1].strip()
    actual_cfg = plistlib.loads(config.read_bytes())['NVRAM']['Add'][NVRAM_GUID]['boot-args']
    if actual_args != bootargs or actual_cfg != bootargs:
        raise ValueError('EFI/NVRAM read-back differs from the Round%d declaration' % ROUND)
    (out / 'token.txt').write_text('0x%08x\n' % args.token, encoding='utf-8')
    if 'kernel_batch' in plan:
        (out / 'batch.txt').write_text('%d\n' % BATCH, encoding='utf-8')
    if 'application_requests' in plan:
        (out / 'requests.txt').write_text('%d\n' % plan['application_requests'], encoding='utf-8')
    (out / 'expected-version.json').write_text(json.dumps(expected, indent=2) + '\n', encoding='utf-8')
    (out / 'deployment.json').write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    (out / 'source-ref.json').write_text(json.dumps(source_ref, indent=2) + '\n', encoding='utf-8')
    daemon = daemon_plist(out, args.peer, args.port)
    generated = out / ('org.example.round%dload.plist' % ROUND)
    generated.write_bytes(plistlib.dumps(daemon, sort_keys=False))
    run(['plutil', '-lint', generated])
    for job in jobs:
        subprocess.run(['sudo', 'launchctl', 'bootout', 'system', str(job)], check=False)
        run(['sudo', 'rm', '-f', job])
    target = Path('/Library/LaunchDaemons') / generated.name
    run(['sudo', 'cp', generated, target])
    run(['sudo', 'chown', 'root:wheel', target])
    run(['sudo', 'chmod', '644', target])
    if plistlib.loads(target.read_bytes()) != daemon:
        raise ValueError('launchd plist read-back differs')
    print('DEPLOY READY; finite RunAtLoad staged, no reboot issued', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
