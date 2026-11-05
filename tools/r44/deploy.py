#!/usr/bin/env python3
"""Install Round44's ordinary per-device mapper using the exact EFI checks.

--check-only prints the same concrete plan without changing the machine.
The token identifies userspace payloads; the kernel receives amdiommu=auto.
"""
import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location('_r44_deployment_base', ROOT / 'tools/r27/deploy.py')
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)

ROUND = 44
BASE_COMMIT = '102560a59bc448ddfd5600d5d958952e4875eb16'
DRIVER_VERSION = '1.1.229'
PROBE_VERSION = '0.53.0'
DEFAULT_TOKEN = 0x44c0de44
REQUIRED_SYMBOLS = ('r44SelectNormalDMA', 'r44MapMemory')


def kernel_bootarg(token):
    return 'amdiommu=auto'


def round_plan():
    return {'round': ROUND, 'driver_mode': 'ordinary-mapped',
            'scope': 'ordinary-device-iomapper', 'token_scope': 'userspace-only',
            'application_requests': 8192, 'idle_seconds': 125,
            'rx_slots': 1024, 'rx_groups': 64, 'rx_group_pages': 16,
            'rx_lifetime': 'driver-resources', 'rx_replacement': 'normal-mbuf',
            'fixed_mappings': 3, 'persistent_mappings': 67,
            'physical_mapping': 'iova-only', 'fixed_dma_iova': True,
            'active_identity_pages': 0, 'experimental_pool': False,
            'legacy_session': False, 'lifecycle': 'normal-ifdown-up',
            'peer_tail_required': False, 'domain_lifetime': 'device-service',
            'iova_pages': 4096, 'live_records': 1024,
            'max_mapping_pages': 32, 'max_mapping_runs': 32}


D.HERE = HERE
D.ROUND = ROUND
D.BASE_COMMIT = BASE_COMMIT
D.DRIVER_VERSION = DRIVER_VERSION
D.PROBE_VERSION = PROBE_VERSION
D.DEFAULT_TOKEN = DEFAULT_TOKEN
D.REQUIRED_SYMBOLS = REQUIRED_SYMBOLS
D.ENTRY_POINTS = ('boot-load.sh', 'load.py', 'common.py')
D.kernel_bootarg = kernel_bootarg
D.round_plan = round_plan
D.__doc__ = __doc__

# Shared exact-disk, installed-bundle and network checks for boot/disarm tools.
NVRAM_GUID = D.NVRAM_GUID
output = D.output
run = D.run
project_path = D.project_path
require_efi = D.require_efi
require_target_ready = D.require_target_ready
require_tso_off = D.require_tso_off
daemon_plist = D.daemon_plist


def main():
    return D.main()


if __name__ == '__main__':
    raise SystemExit(main())
