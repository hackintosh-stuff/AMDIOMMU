#!/usr/bin/env python3
"""Accept ordinary 64-page mappings exercised by sixteen real RX groups.

The complete PT and normal lifecycle checks prove the larger mapping shape.
Keep the eleven DMA32, IVRS and network checks; real system PM stays TODO.
"""
import argparse
import json
import struct
from common import (MAX_MAP_PAGES, MAX_RUNS, RX_GROUPS, RX_GROUP_PAGES, VERSIONS,
                    module, protocol as P, project_path, write_json)

# Actual accepted R48 result-documentation successor.
BASE_COMMIT = 'e7074605b7077304d638f63440fe4467da918c8d'
IOVA_BASE = 0x80000000
R48 = module('_r49_dma32_analyzer', 'tools/r48/analyze.py')


def analyze(cap, *, base_commit=BASE_COMMIT):
    result = R48.R47.analyze(cap, round_id=49, base_commit=base_commit,
                            versions=VERSIONS, protocol=P, iova_base=IOVA_BASE,
                            max_map_pages=MAX_MAP_PAGES, max_runs=MAX_RUNS,
                            rx_groups=RX_GROUPS, rx_group_pages=RX_GROUP_PAGES)
    try:
        check = {'id': 'ordinary-dma32-constraints-and-low-iova', 'state': 'ok',
                 'detail': R48.dma32(cap, max_map_pages=MAX_MAP_PAGES)}
    except (OSError, ValueError, KeyError, IndexError, TypeError, struct.error) as exc:
        check = {'id': 'ordinary-dma32-constraints-and-low-iova',
                 'state': 'FAIL', 'detail': str(exc)}
    result['scope'] = 'r49-large-map-dma32-ivrs-pci-ordinary-ipv6-tcp-tso'
    result['checks'].append(check)
    result['ok'] = result['ok'] and check['state'] == 'ok'
    result['limitations'].append(
        'The current RTL8127 exercises 256 KiB RX mappings with 32-bit DMA constraints; '
        'this does not establish larger transfers or a second-device test.')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture')
    parser.add_argument('--json', dest='output')
    args = parser.parse_args()
    result = analyze(project_path(args.capture))
    if args.output:
        write_json(project_path(args.output), result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
