#!/usr/bin/env python3
"""Accept NPCache-selected map invalidation with synchronous unmap retirement.

Reuse the eleven ordinary checks, unchanged ABI2 and finite TCP workload.
No new real-system-PM or performance threshold is added.
"""
import argparse
import json
import struct
from common import (MAX_MAP_PAGES, MAX_RUNS, PHASES, RX_GROUPS, RX_GROUP_PAGES,
                    VERSIONS, module, protocol as P, project_path,
                    read_snapshot, write_json)

BASE_COMMIT = 'da99156d3e6b20694c88124afb75341f5f437545'
IOVA_BASE = 0x80000000
R48 = module('_r51_dma32_analyzer', 'tools/dma32/analyze.py')
R50 = module('_r51_range_decoder', 'tools/pagetable/analyze.py')
need = R48.R47.need


def invalidation_accounting(label, value):
    """Check actual INV requests; map-ready no longer implies a map CW."""
    p, m = value['probe'], value['mapper']
    npcache = (p['r47-cap-header'] >> 26) & 1
    skipped = p['r51-map-invalidation-skipped']
    need(p['r51-npcache'] == npcache and m['mapOk'] > 0,
         label + ': NPCache selection differs from the discovered PCI capability')
    expected_skipped = 0 if npcache else m['mapOk'] - 1
    expected_invalidations = m['mapOk'] + m['unmapOk'] - expected_skipped
    need(skipped == expected_skipped and
         m['invalidates'] == p['r44-inv-pages-completed'] == expected_invalidations,
         label + ': capability-selected map/unmap INV/CW accounting differs')
    return {'npcache': npcache, 'mapInvalidationsSkipped': skipped,
            'mapInvalidationsCompleted': m['mapOk'] - skipped,
            'unmapInvalidationsCompleted': m['unmapOk'],
            'pageInvalidationsCompleted': expected_invalidations}


def range_invalidation(cap):
    states = {label: read_snapshot(cap / 'snapshots' / label) for label in PHASES}
    detail = {}
    for label, value in states.items():
        p, m = value['probe'], value['mapper']
        accounting = invalidation_accounting(label, value)
        full, ranged = p['r50-inv-full-completed'], p['r50-inv-range-completed']
        requested_pages = p['r50-inv-range-pages']
        need(full == 1 and ranged == accounting['pageInvalidationsCompleted'] - 1 and
             full + ranged == p['r44-inv-pages-completed'] and requested_pages >= ranged,
             label + ': full/range completion accounting differs')
        sequence = p['r50-last-range-sequence']
        address, size = p['r50-last-range-address'], p['r50-last-range-bytes']
        words = [p['r50-last-range-command%d' % i] for i in range(4)]
        start = covered_bytes = 0
        if ranged:
            need(sequence == p['r44-cmd-completion-sequence'] == p['r44-cmd-completed'],
                 label + ': last range is not the latest completed hardware command')
            need(address % 4096 == 0 and size > 0 and size % 4096 == 0 and
                 IOVA_BASE <= address < IOVA_BASE + m['iovaBytes'] and
                 size <= IOVA_BASE + m['iovaBytes'] - address,
                 label + ': last range is not a complete allocated IOVA page span')
            # With NPCache absent, later maps publish PTEs without a command.
            # The latest invalidation therefore belongs to the last unmap,
            # even when lastMap has a newer map-ready timestamp.
            records = [(m['lastUnmap'], m['lastUnmap']['tUnmapComplete'])]
            if accounting['npcache']:
                records.append((m['lastMap'], m['lastMap']['tMapComplete']))
            latest = max(stamp for _, stamp in records)
            need(latest > 0 and any(
                 stamp == latest and address == IOVA_BASE + row['basePage'] * 4096 and
                 size == row['pages'] * 4096 for row, stamp in records),
                 label + ': last range differs from the latest invalidated mapping')
            start, covered_bytes = R50.decode_range(words, p['r44-domain-id'])
            need(start <= address and address + size <= start + covered_bytes and
                 IOVA_BASE <= start and start + covered_bytes <= IOVA_BASE + m['iovaBytes'],
                 label + ': submitted range does not cover the changed pages inside the low pool')
        else:
            need(requested_pages == sequence == address == size == 0 and not any(words),
                 label + ': range evidence exists before the first range command')
        old_count = m['mapOk'] + m['unmapOk'] + 1
        detail[label] = dict(accounting, fullCompleted=full, rangeCompleted=ranged,
                             requestedPages=requested_pages, lastRequestedAddress=address,
                             lastRequestedBytes=size, lastCommandWords=words,
                             encodedStart=start, encodedBytes=covered_bytes,
                             completionSequence=sequence,
                             commandsCompleted=p['r44-cmd-completed'],
                             equivalentR50Commands=old_count,
                             avoidedCommandWaits=accounting['mapInvalidationsSkipped'])
    need(len({row['npcache'] for row in detail.values()}) == 1,
         'PCI NPCache policy changed across ordinary interface down/up')
    for first, last in zip(PHASES, PHASES[1:]):
        need(all(detail[last][key] >= detail[first][key] for key in
                 ('rangeCompleted', 'requestedPages', 'mapInvalidationsSkipped')),
             first + ' -> ' + last + ': invalidation counters went backwards')
    for first, last in (('before', 'pre-down'), ('down', 'after-up')):
        need(detail[last]['rangeCompleted'] > detail[first]['rangeCompleted'] and
             detail[last]['requestedPages'] > detail[first]['requestedPages'],
             first + ' -> ' + last + ': traffic did not exercise synchronous unmap invalidation')
        if not detail[last]['npcache']:
            need(detail[last]['mapInvalidationsSkipped'] > detail[first]['mapInvalidationsSkipped'],
                 first + ' -> ' + last + ': traffic did not exercise the map fast path')
    return detail


def analyze(cap, *, base_commit=BASE_COMMIT):
    result = R48.R47.analyze(cap, round_id=51, base_commit=base_commit,
                            versions=VERSIONS, protocol=P, iova_base=IOVA_BASE,
                            max_map_pages=MAX_MAP_PAGES, max_runs=MAX_RUNS,
                            rx_groups=RX_GROUPS, rx_group_pages=RX_GROUP_PAGES,
                            invalidation_check=invalidation_accounting)
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
            hardware['detail']['npcacheInvalidation'] = range_invalidation(cap)
        except (OSError, ValueError, KeyError, IndexError, TypeError, struct.error) as exc:
            hardware.update(state='FAIL', detail=str(exc))
    result['scope'] = 'r51-npcache-map-invalidation-dma32-ivrs-pci-ordinary-ipv6-tcp-tso'
    result['ok'] = (result['ok'] and len(result['checks']) == 11 and
                    all(item['state'] == 'ok' for item in result['checks']))
    result['limitations'].append(
        'First activation and power transitions retain full invalidation; unmap always '
        'waits for range invalidation before IOVA reuse. NPCache-absent maps publish PTEs '
        'without an INV/CW. Throughput is observed without an improvement threshold.')
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
