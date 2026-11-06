#!/usr/bin/env python3
"""Install Round48 ordinary DMA32 and IPv6 TSO using the existing exact EFI/recovery workflow.

Select existing --local and --peer numeric IPv6 addresses explicitly.
The command reads their address/route state; it does not configure networking.
"""
from pathlib import Path
from common import module

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PREVIOUS = module('_r48_deployment_previous', 'tools/r45/deploy.py')
D = PREVIOUS.D
NETWORK = module('_r48_deployment_network', 'tools/r48/network.py').network
# Actual accepted R47 result-documentation successor.
BASE_COMMIT = '123dea9ddb5f159535f1be5e42f01168203a0850'
DRIVER_VERSION, PROBE_VERSION = '1.1.233', '0.55.0'
LOCAL6 = PEER6 = None
BASE_DAEMON = D.daemon_plist


def require_offloads(info):
    params = info.get('IOKitPersonalities', {}).get('RTL8125', {}).get('Driver Parameters', {})
    if any(params.get(key) is not True for key in ('enableTSO4', 'enableTSO6')):
        raise ValueError('Round48 requires both enableTSO4 and enableTSO6')
    if info.get('OSBundleLibraries', {}).get('org.maz1.AMDMapperProbe') != PROBE_VERSION:
        raise ValueError('Lucy must request the Probe compatibility version ' + PROBE_VERSION)


def add_arguments(parser):
    parser.add_argument('--local', required=True, help='existing numeric IPv6 address on en2')


def check_peer(args):
    global LOCAL6, PEER6
    NETWORK(D.TARGET_IFACE, args.peer, args.local)
    LOCAL6, PEER6 = args.local, args.peer


def round_plan():
    value = PREVIOUS.round_plan()
    value.update(round=48, transport='tcp6', address_family='IPv6',
                 local_ipv6=LOCAL6, peer_ipv6=PEER6,
                 tso4=True, tso6=True, throughput_threshold=None,
                 discovery='acpi-ivrs+pci', dma_address_bits=32,
                 iova_base=0x80000000, iova_bytes=16 << 20,
                 pm_validation='TODO: platform cannot sleep; no PM test is scheduled')
    return value


def daemon_plist(out, peer, port):
    if not LOCAL6 or not PEER6 or peer != PEER6:
        raise ValueError('validate the selected existing IPv6 addresses before staging the job')
    value = BASE_DAEMON(out, peer, port)
    env = value['EnvironmentVariables']
    env.pop('PEER')
    env.update(LOCAL6=LOCAL6, PEER6=PEER6)
    return value


D.HERE, D.ROUND = HERE, 48
D.BASE_COMMIT = BASE_COMMIT
D.DRIVER_VERSION, D.PROBE_VERSION = DRIVER_VERSION, PROBE_VERSION
D.DEFAULT_TOKEN, D.DEFAULT_PORT, D.DEFAULT_PEER = 0x48c0de48, 9114, None
D.TSO4 = D.TSO6 = True
D.REQUIRED_SYMBOLS = ('r47PublishPM', 'r47DiscoverHardware')
D.ENTRY_POINTS = ('boot-load.sh', 'load.py', 'common.py', 'protocol.py', 'network.py')
D.round_plan = round_plan
D.daemon_plist = daemon_plist
D.require_tso_off = require_offloads
D.__doc__ = __doc__

NVRAM_GUID = D.NVRAM_GUID
output, run, project_path = D.output, D.run, D.project_path
require_efi, require_target_ready = D.require_efi, D.require_target_ready


def main():
    return D.main(add_arguments=add_arguments, check_peer=check_peer)


if __name__ == '__main__':
    raise SystemExit(main())
