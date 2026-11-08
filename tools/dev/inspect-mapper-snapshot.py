#!/usr/bin/env python3
"""Check ABI4/ABI5 mapper snapshots saved by ioreg; never touches hardware."""
import argparse
import json
from pathlib import Path
import plistlib
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/ordinary'))
from common import ABI_LAYOUTS, decode, decode_table_segments, record
from analyze import leaves, need


def mapper_entries(value):
    if isinstance(value, list):
        for child in value:
            yield from mapper_entries(child)
    elif isinstance(value, dict):
        if 'mapper-state-raw' in value:
            yield value
        yield from mapper_entries(value.get('IORegistryEntryChildren', []))


def inspect_mapper(entry):
    raw = entry['mapper-state-raw']
    version = struct.unpack_from('<I', raw)[0]
    need(version in (4, 5), 'this inspector requires mapper ABI4 or ABI5')
    mapper = decode(raw, abi=version)
    _, record_bytes, map_pages = ABI_LAYOUTS[version]
    live_raw = entry['mapper-live-raw']
    need(len(live_raw) == mapper['liveCount'] * record_bytes,
         'live record count/size mismatch')
    live = [record(live_raw, offset, map_pages=map_pages)
            for offset in range(0, len(live_raw), record_bytes)]
    value = {'mapper': mapper, 'pt': entry['mapper-page-table-raw']}
    if version >= 5:
        value['pt_segments'] = decode_table_segments(entry['mapper-page-table-segments-raw'])
    actual, reachable_tables = leaves(value)
    expected = {}
    for row in live:
        need(row['recordIndex'] < mapper['capacityMaps'] and
             0 < row['pages'] <= mapper['maxMapPages'] and
             row['basePage'] + row['pages'] <= mapper['capacityPages'],
             'live mapping exceeds usable capacity')
        need(row['state'] == 3, 'live mapping is not confirmed')
        base = mapper['iovaBase'] + row['basePage'] * 4096
        need(row['mapAddress'] == base + (row['firstPA'] & 4095),
             'live mapping address disagrees with its IOVA allocation')
        permissions = ((1 << 61) if row['options'] & 1 else 0) | (
            (1 << 62) if row['options'] & 2 else 0)
        need(permissions, 'live mapping has no DMA permissions')
        for index, physical in enumerate(row['physical'][:row['pages']]):
            address = base + index * 4096
            need(address not in expected and physical > 0 and physical % 4096 == 0,
                 'overlapping IOVA or invalid physical page')
            expected[address] = physical | permissions | (1 << 60) | 1
    need(actual == expected and len(actual) == mapper['livePages'],
         'captured PTE translations differ from the complete live mapping set')
    return {
        'ok': True,
        'registry_entry_id': entry.get('IORegistryEntryID'),
        'requester_id': entry.get('iommu-device-id'),
        'abi': version,
        'snapshot_sequence': mapper['snapshotSequence'],
        'profile': entry.get('iommu-domain-profile', entry.get('iommu-profile')),
        'allocated_profile': entry.get('iommu-profile-allocated'),
        'growth_count': entry.get('iommu-growth-count'),
        'record_growth_count': entry.get('iommu-record-growth-count'),
        'page_growth_count': entry.get('iommu-page-growth-count'),
        'growth_resource': entry.get('iommu-growth-resource'),
        'grown_from_records': entry.get('iommu-growth-from-records'),
        'grown_from_pages': entry.get('iommu-growth-from-pages'),
        'growth_state': entry.get('iommu-growth-state'),
        'capacity_maps': mapper['capacityMaps'],
        'capacity_pages': mapper['capacityPages'],
        'live_maps': mapper['liveCount'],
        'live_pages': mapper['livePages'],
        'root_pa': hex(mapper['rootPA']),
        'table_bytes': mapper['ptBytes'],
        'table_pages': mapper['tablePages'],
        'table_segments': len(value['pt_segments']) if version >= 5 else 1,
        'reachable_table_pages': reachable_tables,
        'metadata_bytes': entry.get('mapper-arena-bytes'),
        'record_storage_bytes': entry.get('mapper-record-storage-bytes'),
        'page_storage_bytes': entry.get('mapper-page-storage-bytes'),
        'page_storage_chunks': entry.get('mapper-page-storage-chunks'),
        'verified_iova_pages': len(actual),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path, help='ioreg -a -l -w0 plist file')
    args = parser.parse_args()
    tree = plistlib.loads(args.capture.read_bytes())
    results, seen = [], set()
    for entry in mapper_entries(tree):
        entry_id = entry.get('IORegistryEntryID')
        if entry_id is not None:
            if entry_id in seen:
                continue
            seen.add(entry_id)
        try:
            results.append(inspect_mapper(entry))
        except (KeyError, ValueError, TypeError, struct.error) as error:
            results.append({'ok': False, 'registry_entry_id': entry_id,
                            'requester_id': entry.get('iommu-device-id'),
                            'error': str(error)})
    need(results, 'no mapper-state-raw entries in the supplied registry capture')
    ok = all(value['ok'] for value in results)
    print(json.dumps({'ok': ok, 'mappers': results}, indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
