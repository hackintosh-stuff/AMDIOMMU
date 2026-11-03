#!/usr/bin/env python3
"""Accept ordinary DMA32 mappings with completed leaf-range invalidation.

Extend the existing hardware-command check; retain eleven ordinary checks,
the 64-page RX shape and the separate real-system-PM TODO.
"""
import argparse
import json
import struct
from common import (MAX_MAP_PAGES, MAX_RUNS, PHASES, RX_GROUPS, RX_GROUP_PAGES,
                    VERSIONS, module, protocol as P, project_path,
                    read_snapshot, write_json)

# Actual accepted R49 result-documentation successor.
BASE_COMMIT = '23973d1652091ba0a671a4442e7a0fd3b2f87146'
IOVA_BASE = 0x80000000
R48 = module('_r50_dma32_analyzer', 'tools/r48/analyze.py')
need = R48.R47.need


def decode_range(words, domain):
    """Decode the submitted AMD command, independently of its encoder.

    For S=1 the first zero address bit above bit11 determines the covered
    power-of-two size. It may cover more pages than the requested mapping.
    """
    need(len(words) == 4 and all(isinstance(w, int) and 0 <= w < (1 << 32)
                               for w in words), 'range command words are not four uint32 values')
    d0, d1, d2, d3 = words
    need(d0 == 0 and d1 == ((3 << 28) | domain),
         'range command opcode/domain or reserved words differ')
    need(d2 & 0xffe == 0, 'ordinary range invalidation sets PDE/GN/reserved bits')
    encoded = (d3 << 32) | d2
    need(encoded < (1 << 52), 'ordinary range uses a full-domain/high-address encoding')
    address = encoded & ~4095
    if not encoded & 1:
        return address, 4096
    first_zero = 12
    while encoded & (1 << first_zero):
        first_zero += 1
    size = 1 << (first_zero + 1)
    return address & ~(size - 1), size


def range_invalidation(cap):
    states = {label: read_snapshot(cap / 'snapshots' / label) for label in PHASES}
    detail = {}
    for label, value in states.items():
        p, m = value['probe'], value['mapper']
        full = p['r50-inv-full-completed']
        ranged = p['r50-inv-range-completed']
        requested_pages = p['r50-inv-range-pages']
        need(full == 1 and ranged > 0 and
             ranged == m['mapOk'] + m['unmapOk'] - 1 and
             full + ranged == p['r44-inv-pages-completed'],
             label + ': full/range completion accounting differs')
        need(requested_pages >= ranged,
             label + ': cumulative requested range pages are incomplete')
        sequence = p['r50-last-range-sequence']
        need(sequence == p['r44-cmd-completion-sequence'] == p['r44-cmd-completed'],
             label + ': last range is not the latest completed command')
        address = p['r50-last-range-address']
        size = p['r50-last-range-bytes']
        need(address % 4096 == 0 and size > 0 and size % 4096 == 0 and
             IOVA_BASE <= address < IOVA_BASE + m['iovaBytes'] and
             size <= IOVA_BASE + m['iovaBytes'] - address,
             label + ': last range is not a complete allocated IOVA page span')
        records = ((m['lastMap'], m['lastMap']['tMapComplete']),
                   (m['lastUnmap'], m['lastUnmap']['tUnmapComplete']))
        latest = max(stamp for _, stamp in records)
        need(any(stamp == latest and address == IOVA_BASE + row['basePage'] * 4096 and
                 size == row['pages'] * 4096 for row, stamp in records),
             label + ': last range differs from the latest completed map/unmap pages')
        words = [p['r50-last-range-command%d' % i] for i in range(4)]
        start, covered_bytes = decode_range(words, p['r44-domain-id'])
        need(start <= address and address + size <= start + covered_bytes and
             IOVA_BASE <= start and start + covered_bytes <= IOVA_BASE + m['iovaBytes'],
             label + ': submitted range does not cover the changed pages inside the low pool')
        detail[label] = {'fullCompleted': full, 'rangeCompleted': ranged,
                         'requestedPages': requested_pages, 'lastRequestedAddress': address,
                         'lastRequestedBytes': size, 'lastCommandWords': words,
                         'encodedStart': start, 'encodedBytes': covered_bytes,
                         'completionSequence': sequence}
    for first, last in zip(PHASES, PHASES[1:]):
        need(detail[last]['rangeCompleted'] >= detail[first]['rangeCompleted'] and
             detail[last]['requestedPages'] >= detail[first]['requestedPages'],
             first + ' -> ' + last + ': range completion counters went backwards')
    for first, last in (('before', 'pre-down'), ('down', 'after-up')):
        need(detail[last]['rangeCompleted'] > detail[first]['rangeCompleted'] and
             detail[last]['requestedPages'] > detail[first]['requestedPages'],
             first + ' -> ' + last + ': traffic did not exercise range invalidation')
    return detail


def analyze(cap, *, base_commit=BASE_COMMIT):
    result = R48.R47.analyze(cap, round_id=50, base_commit=base_commit,
                            versions=VERSIONS, protocol=P, iova_base=IOVA_BASE,
                            max_map_pages=MAX_MAP_PAGES, max_runs=MAX_RUNS,
                            rx_groups=RX_GROUPS, rx_group_pages=RX_GROUP_PAGES)
    try:
        check = {'id': 'ordinary-dma32-constraints-and-low-iova', 'state': 'ok',
                 'detail': R48.dma32(cap, max_map_pages=MAX_MAP_PAGES)}
    except (OSError, ValueError, KeyError, IndexError, TypeError, struct.error) as exc:
        check = {'id': 'ordinary-dma32-constraints-and-low-iova',
                 'state': 'FAIL', 'detail': str(exc)}
    result['checks'].append(check)
    hardware = next((item for item in result['checks']
                     if item['id'] == 'hardware-command-completion-and-no-target-faults'), None)
    if hardware is not None and hardware['state'] == 'ok':
        try:
            hardware['detail']['rangeInvalidation'] = range_invalidation(cap)
        except (OSError, ValueError, KeyError, IndexError, TypeError, struct.error) as exc:
            hardware.update(state='FAIL', detail=str(exc))
    result['scope'] = 'r50-range-invalidation-dma32-ivrs-pci-ordinary-ipv6-tcp-tso'
    result['ok'] = (result['ok'] and len(result['checks']) == 11 and
                    all(item['state'] == 'ok' for item in result['checks']))
    result['limitations'].append(
        'Commands request leaf-range invalidation; hardware may invalidate a wider cache range. '
        'The required command/CW count is unchanged; throughput has no improvement threshold.')
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
