#!/usr/bin/env python3
"""Stage the mixed-driver run and replace the old RTL8111 EFI injection with its new AuxKC bundle."""
import argparse
from pathlib import Path
import plistlib
import re
import sys
from common import (BASE_COMMIT, VERSIONS, configuration, module, project_path,
                    roles, selected_drivers, registry, selector, write_json)

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
D = module('_r53_deploy_base', 'tools/r27/deploy.py')
N = module('_r53_deploy_network', 'tools/r53/network.py')
RTL8111_ID = 'com.insanelymac.RealtekRTL8111'
CONFIG, EFI_INJECTIONS = None, []
PREVIOUSLY_ABSENT = []


def require_offloads(info):
    params = info.get('IOKitPersonalities', {}).get('RTL8125', {}).get('Driver Parameters', {})
    if any(params.get(key) is not True for key in ('enableTSO4', 'enableTSO6')):
        raise ValueError('R53 Lucy requires enableTSO4=true and enableTSO6=true')
    if info.get('OSBundleLibraries', {}).get('org.example.AMDMapperProbe') != VERSIONS['AMDMapperProbe']:
        raise ValueError('Lucy Probe compatibility version differs')


BASE_BUNDLE_IDENTITY = D.bundle_identity


def bundle_identity(bundle, version, symbol):
    if bundle.stem == 'RealtekRTL8111':
        info = plistlib.loads((bundle / 'Contents/Info.plist').read_bytes())
        if (info.get('CFBundleIdentifier') != RTL8111_ID or
                info.get('OSBundleLibraries', {}).get('org.example.AMDMapperProbe') != VERSIONS['AMDMapperProbe']):
            raise ValueError('RTL8111 bundle identity or mapper startup dependency differs')
    return BASE_BUNDLE_IDENTITY(bundle, version, symbol)


def management_ready(text, _unused_default_route):
    address = re.escape(CONFIG['management']['address'])
    return bool('status: active' in text and re.search(r'\binet6?\s+' + address + r'(?:\s|%)', text))


def require_target_ready(text):
    if 'status: active' not in text or not re.search(r'\bmtu\s+1500\b', text):
        raise ValueError('the selected RTL8111 endpoint needs its existing active MTU1500 link')


def efi_injections(config, efi):
    """Read enabled entries by bundle identifier; only the RTL8111 entries will change."""
    root = (efi / 'EFI/OC/Kexts').resolve()
    found = []
    for index, row in enumerate(config.get('Kernel', {}).get('Add', [])):
        if row.get('Enabled') is not True:
            continue
        bundle_path = row.get('BundlePath', '')
        info_path = (root / bundle_path / row.get('PlistPath', 'Contents/Info.plist')).resolve()
        info_path.relative_to(root)
        if not info_path.is_file():
            continue
        info = plistlib.loads(info_path.read_bytes())
        if info.get('CFBundleIdentifier') == RTL8111_ID:
            found.append({'index': index, 'bundle_path': bundle_path,
                          'version': info.get('CFBundleVersion'),
                          'identifier': RTL8111_ID})
    return found


def check_endpoints(args):
    global EFI_INJECTIONS, PREVIOUSLY_ABSENT
    selected_drivers(registry(), CONFIG)
    for endpoint in roles(CONFIG).values():
        N.network(endpoint)
    efi = Path(args.efi).expanduser().resolve()
    config = plistlib.loads((efi / 'EFI/OC/config.plist').read_bytes())
    EFI_INJECTIONS = efi_injections(config, efi)
    installed = Path('/Library/Extensions/RealtekRTL8111.kext')
    PREVIOUSLY_ABSENT = [] if installed.exists() else [str(installed)]


def deployment_bundles():
    return [(ROOT / 'build-lucy/RTL812xLucy.kext', VERSIONS['RTL812xLucy'], 'r47PublishPM'),
            (ROOT / 'build-m1a/AMDMapperProbe.kext', VERSIONS['AMDMapperProbe'], 'r52PublishDomains'),
            (ROOT / 'build-rtl8111/RealtekRTL8111.kext', VERSIONS['RealtekRTL8111'], 'r53SnapshotAction')]


def recovery_sources(aux, config, targets, jobs):
    # The old RTL8111 may be EFI-only. Its EFI file stays in place; restoring
    # the exact old config re-enables it, and absent L/E targets are recorded.
    kept = [target for target in targets
            if target.name != 'RealtekRTL8111.kext' or target.exists()]
    return [aux, config] + kept + jobs


def record_recovery_plan(backup, plan, sources, previous_boot_args):
    write_json(backup / 'recovery-plan.json', {
        'round': 53, 'previous_boot_args': previous_boot_args,
        'previously_absent_targets': PREVIOUSLY_ABSENT,
        'efi_rtl8111_entries': EFI_INJECTIONS,
        'recovery_sources': [{'source': str(source), 'saved_as': source.name} for source in sources],
        'deployment_plan': plan})


def updated_boot_args(current_args, _tokenarg):
    kept = [arg for arg in current_args.split()
            if not arg.startswith(('amdiommu=', 'amdiommu_devices='))]
    return ' '.join(kept + ['amdiommu=auto', 'amdiommu_devices=' + selector(CONFIG)])


def write_boot_config(config, cfg, bootargs, _tokenarg):
    entries = cfg.get('Kernel', {}).get('Add', [])
    for selected in EFI_INJECTIONS:
        row = entries[selected['index']]
        if row.get('BundlePath') != selected['bundle_path']:
            raise ValueError('RTL8111 EFI entry changed after the concrete deployment plan')
        row['Enabled'] = False
    cfg['NVRAM']['Add'][D.NVRAM_GUID]['boot-args'] = bootargs
    temp = config.with_name(config.name + '.r53.tmp')
    temp.write_bytes(plistlib.dumps(cfg, sort_keys=False))
    D.run(['plutil', '-lint', temp])
    temp.replace(config)
    back = plistlib.loads(config.read_bytes())
    if (back['NVRAM']['Add'][D.NVRAM_GUID]['boot-args'] != bootargs or
            any(back['Kernel']['Add'][row['index']]['Enabled'] is not False for row in EFI_INJECTIONS)):
        raise ValueError('RTL8111 EFI injection/selector read-back differs')


def round_plan():
    return {'round': 53, 'transport': 'tcp6', 'config': CONFIG,
            'requester_selector': selector(CONFIG), 'transfer_bytes': 64 << 20,
            'mapper_abi': 2, 'domains': 2, 'drivers': ['RTL8111', 'RTL8125'],
            'controller': 'one shared device table, event buffer and command ring',
            'lifecycle': 'RTL8111 down; RTL8125 completes traffic; RTL8111 up',
            'efi_rtl8111_entries_disabled': EFI_INJECTIONS,
            'previously_absent_targets': PREVIOUSLY_ABSENT,
            'source_snapshots_in_evidence': False, 'pm_validation': 'not scheduled'}


def daemon_plist(out, _unused_peer, _unused_port):
    config_path = out / 'endpoints.json'
    write_json(config_path, CONFIG)
    return {'Label': 'org.example.round53load',
            'ProgramArguments': ['/bin/sh', str(HERE / 'boot-load.sh'),
                                 out.relative_to(ROOT).as_posix(), config_path.relative_to(ROOT).as_posix()],
            'WorkingDirectory': str(ROOT),
            'EnvironmentVariables': {'PYTHON': str(Path(sys.executable).resolve()),
                                     'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'},
            'RunAtLoad': True, 'KeepAlive': False,
            'StandardOutPath': str(out / 'launchd.out'), 'StandardErrorPath': str(out / 'launchd.err')}


D.HERE, D.ROUND, D.BASE_COMMIT = HERE, 53, BASE_COMMIT
D.DRIVER_VERSION, D.PROBE_VERSION = VERSIONS['RTL812xLucy'], VERSIONS['AMDMapperProbe']
D.DEFAULT_TOKEN, D.DEFAULT_PORT, D.DEFAULT_PEER = 0x53c0de53, 9120, 'endpoint-config'
D.TSO4 = D.TSO6 = True
D.ENTRY_POINTS = ('boot-load.sh', 'load.py', 'common.py', 'protocol.py', 'network.py')
D.kernel_bootarg = lambda token: 'amdiommu=auto'
D.deployment_bundles, D.recovery_sources = deployment_bundles, recovery_sources
D.updated_boot_args, D.write_boot_config = updated_boot_args, write_boot_config
D.record_recovery_plan = record_recovery_plan
D.round_plan, D.daemon_plist, D.bundle_identity = round_plan, daemon_plist, bundle_identity
D.require_tso_off, D.management_ready = require_offloads, management_ready
D.require_target_ready = require_target_ready
D.__doc__ = __doc__
NVRAM_GUID, output, run, require_efi = D.NVRAM_GUID, D.output, D.run, D.require_efi


def main():
    global CONFIG
    initial = argparse.ArgumentParser(add_help=False)
    initial.add_argument('--config')
    selected, _ = initial.parse_known_args()
    if selected.config:
        CONFIG = configuration(project_path(selected.config))
        management = CONFIG.get('management', {})
        if not management.get('interface') or not management.get('address'):
            raise ValueError('use the existing independent management interface/address')
        D.MGMT_IFACE, D.MGMT_ADDR = management['interface'], management['address']
        D.TARGET_IFACE = roles(CONFIG)['a']['interface']
    def add_arguments(parser):
        parser.add_argument('--config', required=True, help='existing mixed endpoints and management JSON')
    return D.main(add_arguments=add_arguments, check_peer=check_endpoints)


if __name__ == '__main__':
    raise SystemExit(main())
