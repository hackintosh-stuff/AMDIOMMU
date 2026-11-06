#!/usr/bin/env python3
"""Accept ordinary 32-bit DMA constraints with low IOVAs and IPv6 TCP/TSO.

The existing IVRS and network checks remain; real system PM stays TODO.
The source baseline is the actual accepted R47 result-documentation successor.
"""
import argparse
import json
import struct
from common import (PHASES, VERSIONS, module, protocol as P, project_path,
                    read_snapshot, write_json)

BASE_COMMIT = '123dea9ddb5f159535f1be5e42f01168203a0850'
IOVA_BASE, IOVA_BYTES, DMA_LIMIT = 0x80000000, 16 << 20, 1 << 32
R47 = module('_r48_ivrs_analyzer', 'tools/discovery/analyze.py')
need = R47.need


def dma32(cap, *, max_map_pages=32):
    phases, observed_high_pages, previous = {}, 0, None
    for label in PHASES:
        value = read_snapshot(cap / 'snapshots' / label)
        m, p, d = value['mapper'], value['probe'], value['driver']
        need(d['rtl812x-r48-dma-address-bits'] == 32,
             label + ': the ordinary driver command address constraint is not 32 bits')
        need((m['iovaBase'], m['iovaBytes']) == (IOVA_BASE, IOVA_BYTES) and
             IOVA_BASE + IOVA_BYTES <= DMA_LIMIT, label + ': low IOVA pool differs')
        count, high_count, high_pages = (p['r48-map32-ok'], p['r48-map-high-pa-ok'],
                                         p['r48-mapped-high-pa-pages'])
        need(count == m['mapOk'] > 0 and
             p['r48-map-min-bits'] == p['r48-map-max-bits'] == 32,
             label + ': successful mapper calls did not all request 32-bit addresses')
        need(0 <= high_count <= count and high_count <= high_pages <= high_count * max_map_pages,
             label + ': high physical-page mapping counters differ')
        current = count, high_count, high_pages
        need(previous is None or all(a <= b for a, b in zip(previous, current)),
             label + ': DMA32 lifetime counters regressed')
        previous = current
        records = list(value['live']) + [m['lastMap']]
        if m['unmapOk']:
            records.append(m['lastUnmap'])
        for row in records:
            address, length = row['mapAddress'], row['mapLength']
            need(IOVA_BASE <= address < DMA_LIMIT and length > 0 and
                 address + length <= IOVA_BASE + IOVA_BYTES <= DMA_LIMIT,
                 label + ': live or last packet mapping exceeds the 32-bit IOVA pool')
        live_high_pages = sum(pa >= DMA_LIMIT for row in value['live']
                              for pa in row['physical'][:row['pages']])
        live_high_maps = sum(any(pa >= DMA_LIMIT for pa in row['physical'][:row['pages']])
                             for row in value['live'])
        max_physical_page = max(pa for row in value['live']
                                for pa in row['physical'][:row['pages']])
        need(high_count >= live_high_maps and high_pages >= live_high_pages,
             label + ': cumulative high-PA evidence is smaller than the current live set')
        # The inherited whole-PT check proves these physical pages really are
        # the targets of the captured low IOVAs, rather than merely counters.
        observed_high_pages += live_high_pages
        phases[label] = {'map32Ok': count, 'mapHighPAOk': high_count,
                         'mappedHighPAPages': high_pages, 'liveHighPAPages': live_high_pages,
                         'liveHighPAMaps': live_high_maps, 'checkedRecords': len(records),
                         'maxLivePhysicalPage': max_physical_page,
                         'lastMapAddress': m['lastMap']['mapAddress'],
                         'lastMapLength': m['lastMap']['mapLength'],
                         'maxMappedAddressExclusive': max(row['mapAddress'] + row['mapLength']
                                                         for row in records)}
    return {'requestedBits': 32, 'iovaBase': IOVA_BASE, 'iovaBytes': IOVA_BYTES,
            'highPhysicalPagesObserved': observed_high_pages > 0,
            'highPhysicalEvidence': ('observed-in-complete-live-and-pt' if observed_high_pages else
                                     'not-present-in-captured-live-set'),
            'phases': phases}


def analyze(cap, *, base_commit=BASE_COMMIT):
    result = R47.analyze(cap, round_id=48, base_commit=base_commit,
                         versions=VERSIONS, protocol=P, iova_base=IOVA_BASE)
    try:
        check = {'id': 'ordinary-dma32-constraints-and-low-iova',
                 'state': 'ok', 'detail': dma32(cap)}
    except (OSError, ValueError, KeyError, IndexError, TypeError, struct.error) as exc:
        check = {'id': 'ordinary-dma32-constraints-and-low-iova',
                 'state': 'FAIL', 'detail': str(exc)}
    result['scope'] = 'r48-dma32-ivrs-pci-ordinary-ipv6-tcp-tso'
    result['checks'].append(check)
    result['ok'] = result['ok'] and check['state'] == 'ok'
    result['limitations'].append(
        'The current RTL8127 uses 32-bit IODMACommand constraints; this is not a second-device test.')
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
