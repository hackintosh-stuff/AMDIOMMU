#!/usr/bin/env python3
"""Stage the finite two-endpoint R52 run using the existing exact EFI recovery workflow."""
import argparse
from pathlib import Path
import re
import sys
from common import BASE_COMMIT, VERSIONS, configuration, module, project_path, roles, selected_drivers, registry, write_json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
D = module('_r52_deploy_base', 'tools/r27/deploy.py')
N = module('_r52_deploy_network', 'tools/r52/network.py')
DRIVER_VERSION, PROBE_VERSION = VERSIONS['RTL812xLucy'], VERSIONS['AMDMapperProbe']
CONFIG = None


def require_offloads(info):
    params = info.get('IOKitPersonalities', {}).get('RTL8125', {}).get('Driver Parameters', {})
    if any(params.get(key) is not True for key in ('enableTSO4', 'enableTSO6')):
        raise ValueError('R52 requires enableTSO4=true and enableTSO6=true')
    if info.get('OSBundleLibraries', {}).get('org.example.AMDMapperProbe') != PROBE_VERSION:
        raise ValueError('Lucy Probe compatibility version differs')


def management_ready(text, _unused_default_route):
    address = re.escape(CONFIG['management']['address'])
    return bool('status: active' in text and re.search(r'\binet6?\s+' + address + r'(?:\s|%)', text))


def require_target_ready(text):
    if 'status: active' not in text or not re.search(r'\bmtu\s+1500\b', text):
        raise ValueError('selected down target must already have an active MTU1500 link')


def check_endpoints(_args):
    selected_drivers(registry(), CONFIG)
    for endpoint in roles(CONFIG).values():
        N.network(endpoint)


def round_plan():
    return {'round': 52, 'transport': 'tcp6', 'config': CONFIG, 'tso4': True, 'tso6': True,
            'transfer_bytes': 64 << 20, 'mapper_abi': 2, 'domains': 2,
            'controller': 'shared device table, event buffer and command ring',
            'lifecycle': 'selected target down; other endpoint completes traffic; target up',
            'source_snapshots_in_evidence': False, 'pm_validation': 'not scheduled'}


def daemon_plist(out, _unused_peer, _unused_port):
    config_path = out / 'endpoints.json'
    write_json(config_path, CONFIG)
    return {'Label': 'org.example.round52load',
            'ProgramArguments': ['/bin/sh', str(HERE / 'boot-load.sh'),
                                 out.relative_to(ROOT).as_posix(), config_path.relative_to(ROOT).as_posix()],
            'WorkingDirectory': str(ROOT),
            'EnvironmentVariables': {'PYTHON': str(Path(sys.executable).resolve()),
                                     'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'},
            'RunAtLoad': True, 'KeepAlive': False,
            'StandardOutPath': str(out / 'launchd.out'), 'StandardErrorPath': str(out / 'launchd.err')}


D.HERE, D.ROUND, D.BASE_COMMIT = HERE, 52, BASE_COMMIT
D.DRIVER_VERSION, D.PROBE_VERSION = DRIVER_VERSION, PROBE_VERSION
D.DEFAULT_TOKEN, D.DEFAULT_PORT, D.DEFAULT_PEER = 0x52c0de52, 9118, 'endpoint-config'
D.TSO4 = D.TSO6 = True
D.ENTRY_POINTS = ('boot-load.sh', 'load.py', 'common.py', 'protocol.py', 'network.py')
D.REQUIRED_SYMBOLS = ('r47PublishPM', 'r52PublishDomains')
D.kernel_bootarg = lambda token: 'amdiommu=auto'
D.round_plan, D.daemon_plist = round_plan, daemon_plist
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
            raise ValueError('deployment config needs the existing independent management interface/address')
        D.MGMT_IFACE, D.MGMT_ADDR = management['interface'], management['address']
        D.TARGET_IFACE = roles(CONFIG)['a']['interface']
    def add_arguments(parser):
        parser.add_argument('--config', required=True, help='existing two-endpoint and management JSON')
    return D.main(add_arguments=add_arguments, check_peer=check_endpoints)


if __name__ == '__main__':
    raise SystemExit(main())
