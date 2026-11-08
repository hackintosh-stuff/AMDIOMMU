#!/usr/bin/env python3
"""Ordinary per-device mapper capture; archived ABI1 remains the default."""
import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
VERSION, SNAPSHOT_BYTES, RECORD_BYTES = 1, 960, 360
ABI_LAYOUTS = {1: (960, 360, 32), 2: (1472, 616, 64), 3: (2496, 1128, 128),
               4: (4544, 2152, 256), 5: (4544, 2152, 256)}
VERSIONS = {'RTL812xLucy': '1.1.229', 'AMDMapperProbe': '0.53.0'}
PHASES = ('phase1', 'phase2', 'pre-down', 'down', 'after-up')
EXPORTS = {'r44-mapper-raw': 'mapper.bin', 'r44-live-raw': 'live.bin',
           'r44-pt-raw': 'pt.bin'}


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


sys.path.insert(0, str(ROOT / 'tools/base'))
DBG = module('_amdiommu_dbgmask', 'tools/dbgmask.py')
protocol = module('_r44_protocol', 'tools/base/protocol.py')
load_helpers = module('_r44_load_helpers', 'tools/base/load.py')
session = module('_r44_registry_rpc', 'tools/session/session.py')


def project_path(value):
    path = Path(value)
    if path.is_absolute():
        raise ValueError('use a repository-relative path: ' + value)
    path = (ROOT / path).resolve()
    path.relative_to(ROOT)
    return path


def write_json(path, value):
    path.write_bytes((json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode('utf-8'))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unpack(names, fmt, data, offset=0):
    return dict(zip(names.split(), struct.unpack_from('<' + fmt, data, offset)))


def record(data, offset=0, *, map_pages=32):
    row = unpack('handle firstPA mapAddress mapLength descriptorOffset length '
                 'tPublish tMapComplete tClear tUnmapComplete', '10Q', data, offset)
    row.update(unpack('recordIndex basePage pages runs options state', '6I', data, offset + 80))
    row['physical'] = list(struct.unpack_from('<%dQ' % map_pages, data, offset + 104))
    return row


def decode(data, *, abi=1):
    snapshot_bytes, record_bytes, map_pages = ABI_LAYOUTS[abi]
    if len(data) != snapshot_bytes:
        raise ValueError('ordinary mapper snapshot must be %d bytes' % snapshot_bytes)
    result = unpack('version bytes flags capacityMaps capacityPages maxMapPages maxRuns liveCount', '8I', data)
    if (result['version'], result['bytes']) != (abi, snapshot_bytes):
        raise ValueError('ordinary mapper ABI%d required' % abi)
    result.update(unpack('iovaBase iovaBytes rootPA ptBytes', '4Q', data, 32))
    result.update(unpack('rootLevel tablePages livePages peakPages peakMaps maxObservedPages '
                         'maxObservedRuns reserved', '8I', data, 64))
    result.update(unpack('mapCalls mapOk mapRejected unmapCalls unmapOk unmapRejected '
                         'invalidates invalidateFailures reusedAllocations offsetMaps fragmentedMaps walks',
                         '12Q', data, 96))
    result.update(unpack('preparedAt firstMapAt lastMapAt lastUnmapAt snapshotSequence snapshotTime',
                         '6Q', data, 192))
    result['lastMap'] = record(data, 240, map_pages=map_pages)
    result['lastUnmap'] = record(data, 240 + record_bytes, map_pages=map_pages)
    return result


def decode_table_segments(data):
    """ABI5 page-table blocks: physical base, byte offset in pt.bin, byte size."""
    if not data or len(data) % 24:
        raise ValueError('page-table segments must contain <QQQ records')
    return [dict(zip(('physicalBase', 'offset', 'bytes'), row))
            for row in struct.iter_unpack('<QQQ', data)]


def registry(class_name, marker):
    data = plistlib.loads(subprocess.check_output(['ioreg', '-a', '-l', '-w0', '-r', '-c', class_name]))
    DBG.require(DBG.BASE, 'ioreg %s' % class_name, data)
    found = []

    def walk(node):
        if isinstance(node, dict):
            if marker in node:
                found.append(node)
            for child in node.get('IORegistryEntryChildren', []):
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)
    walk(data)
    if len(found) != 1:
        raise ValueError('expected one registry entry for ' + marker)
    return found[0]


def snapshot(parent, label, driver_prefixes=('rtl812x-r44-',),
             probe_prefixes=('r44-',), extra_exports=None, *, abi=1):
    """One explicit read-only export; production mapping has no capture limit."""
    out = parent / label
    out.mkdir(parents=True, exist_ok=False)
    session.set_boolean_property('RefreshSnapshot')  # Formerly R44Snapshot.
    probe = registry('org_maz1_AMDMapperProbe', 'r44-mode')
    DBG.require(DBG.MAPPING | DBG.RAW, 'ordinary mapper snapshot', probe)
    driver = registry('RTL8125', 'rtl812x-r44-mapper-found')
    exports = {}
    requested = dict(EXPORTS)
    if abi >= 5:
        requested['mapper-page-table-segments-raw'] = 'pt-segments.bin'
    if extra_exports:
        requested.update(extra_exports)
    for key, name in requested.items():
        value = probe.get(key)
        if not isinstance(value, bytes):
            raise ValueError('missing raw export ' + key)
        (out / name).write_bytes(value)
        exports[name] = {'bytes': len(value), 'sha256': sha(value)}
    def scalars(props, prefix):
        return {key: value for key, value in props.items()
                if key.startswith(prefix) and isinstance(value, (str, int, bool))}
    value = {'label': label, 'captured_ns': load_helpers.now(), 'exports': exports,
             'probe': scalars(probe, probe_prefixes), 'driver': scalars(driver, driver_prefixes)}
    write_json(out / 'snapshot.json', value)
    value['mapper'] = decode(probe['r44-mapper-raw'], abi=abi)
    return value


def read_snapshot(path, *, abi=1):
    value = json.loads((path / 'snapshot.json').read_text())
    names = list(EXPORTS.values())
    if abi >= 5:
        names.append('pt-segments.bin')
    for name in names:
        data = (path / name).read_bytes()
        if value['exports'].get(name) != {'bytes': len(data), 'sha256': sha(data)}:
            raise ValueError('snapshot digest mismatch: ' + str(path / name))
    value['mapper'] = decode((path / 'mapper.bin').read_bytes(), abi=abi)
    _, record_bytes, map_pages = ABI_LAYOUTS[abi]
    live = (path / 'live.bin').read_bytes()
    if len(live) != value['mapper']['liveCount'] * record_bytes:
        raise ValueError('live record count/size mismatch')
    value['live'] = [record(live, i, map_pages=map_pages) for i in range(0, len(live), record_bytes)]
    value['pt'] = (path / 'pt.bin').read_bytes()
    if abi >= 5:
        value['pt_segments'] = decode_table_segments((path / 'pt-segments.bin').read_bytes())
    return value


def identity(value):
    p = value['probe']
    return tuple(p[key] for key in ('r44-target-devid', 'r44-domain-id', 'r44-root-pa',
                                    'r44-device-table-pa', 'r44-command-pa',
                                    'r44-controller-ready-time', 'r44-dte-active-time'))


def active(value, *, min_maps=67):
    p, d, m = value['probe'], value['driver'], value['mapper']
    return (p.get('r44-mode') == 'auto' and p.get('r44-state') == 'active' and
            p.get('r44-controller-ready') == p.get('r44-dte-active') == 'yes' and
            d.get('rtl812x-r44-mapper-found') == d.get('rtl812x-r44-mapped-dma') == 1 and
            m['flags'] == 3 and m['liveCount'] >= min_maps and not m['invalidateFailures'])
