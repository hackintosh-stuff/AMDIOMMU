#!/usr/bin/env python3
"""Install Round45's IPv4 TSO path using the exact EFI and recovery checks.

--check-only prints the concrete plan without changing the machine.
The token identifies userspace TCP payloads; the kernel uses amdiommu=auto.
"""
import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location('_r45_deployment_base', ROOT / 'tools/base/deploy.py')
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)

ROUND = 45
BASE_COMMIT = '035d1dd0f5e60afbc5f2715de3f425cb694d3f56'
DRIVER_VERSION = '1.1.230'
PROBE_VERSION = '0.53.0'
DEFAULT_TOKEN = 0x45c0de45
DEFAULT_PORT = 9111
REQUIRED_SYMBOLS = ('r45PublishTSO', 'r44MapMemory')


def kernel_bootarg(token):
    return 'amdiommu=auto'


def require_offloads(info):
    """Check the intended IPv4 TSO mode and the unchanged mapper dependency."""
    params = info.get('IOKitPersonalities', {}).get('RTL8125', {}).get('Driver Parameters', {})
    if params.get('enableTSO4') is not True or params.get('enableTSO6') is not False:
        raise ValueError('Round45 requires enableTSO4=true and enableTSO6=false')
    if info.get('OSBundleLibraries', {}).get('org.maz1.AMDMapperProbe') != PROBE_VERSION:
        raise ValueError('Round45 Lucy must request AMDMapperProbe ' + PROBE_VERSION)


def round_plan():
    return {'round': ROUND, 'driver_mode': 'ordinary-mapped',
            'scope': 'ordinary-device-iomapper', 'token_scope': 'userspace-only',
            'transport': 'tcp4', 'idle_seconds': 0,
            'transfer_bytes': {'before-upload': 128 * 1024 * 1024,
                               'before-download': 128 * 1024 * 1024,
                               'after-up-upload': 8 * 1024 * 1024,
                               'after-up-download': 8 * 1024 * 1024},
            'rx_slots': 1024, 'rx_groups': 64, 'rx_group_pages': 16,
            'rx_lifetime': 'driver-resources', 'rx_replacement': 'normal-mbuf',
            'fixed_mappings': 3, 'persistent_mappings': 67,
            'physical_mapping': 'iova-only', 'fixed_dma_iova': True,
            'active_identity_pages': 0, 'experimental_pool': False,
            'legacy_session': False, 'lifecycle': 'normal-ifdown-up',
            'peer_tail_required': False, 'peer_log_required': True,
            'domain_lifetime': 'device-service',
            'iova_pages': 4096, 'live_records': 1024,
            'max_mapping_pages': 32, 'max_mapping_runs': 32}


D.HERE = HERE
D.ROUND = ROUND
D.BASE_COMMIT = BASE_COMMIT
D.DRIVER_VERSION = DRIVER_VERSION
D.PROBE_VERSION = PROBE_VERSION
D.DEFAULT_TOKEN = DEFAULT_TOKEN
D.DEFAULT_PORT = DEFAULT_PORT
D.TSO4, D.TSO6 = True, False
D.REQUIRED_SYMBOLS = REQUIRED_SYMBOLS
D.ENTRY_POINTS = ('boot-load.sh', 'load.py', 'common.py', 'protocol.py')
D.kernel_bootarg = kernel_bootarg
D.round_plan = round_plan
# The base helper's name is historical: its callback now checks this round's
# configured offloads rather than requiring both TSO modes to be disabled.
D.require_tso_off = require_offloads
D.__doc__ = __doc__

# Shared exact-disk, installed-bundle and network checks for boot/disarm tools.
NVRAM_GUID = D.NVRAM_GUID
output = D.output
run = D.run
project_path = D.project_path
require_efi = D.require_efi
require_target_ready = D.require_target_ready
daemon_plist = D.daemon_plist


def main():
    return D.main()


if __name__ == '__main__':
    raise SystemExit(main())
