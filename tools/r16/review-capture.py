#!/usr/bin/env python3
"""Read-only concise independent raw review including archive hash integrity."""
import hashlib
import json
from pathlib import Path
import re
import sys
sys.dont_write_bytecode = True
import analyze as X

cap = Path(sys.argv[1])
h, rows = X.decode_domain((cap / 'r16-domain-raw.bin').read_bytes())
dh, driver = X.decode_driver((cap / 'r16-driver-raw.bin').read_bytes())
manifest = (cap / 'MANIFEST.txt').read_text(encoding='utf-8')
files, errors = 0, []
for digest, size, name in re.findall(r'^\s+([0-9a-f]{64})\s+(\d+)\s+(.+)$', manifest, re.M):
    path = cap / name
    X.need(path.resolve().is_relative_to(cap.resolve()), 'manifest path escapes capture')
    data = path.read_bytes()
    files += 1
    if len(data) != int(size) or hashlib.sha256(data).hexdigest() != digest:
        errors.append(name)
summary = []
for row, d in zip(rows, driver):
    summary.append({'req': row['req'], 'handle': row['handle'],
        'segments': [{'iova': hex(s['iova']), 'pa': hex(s['pa']), 'bytes': s['bytes'],
                      'iovaEndExclusive': hex(s['iova'] + s['bytes'])} for s in row['segments'][:row['count']]],
        'mapPte': [hex(p) for p in row['mapPte'][:row['pages']]],
        'mapPublish': row['tMapPublish'], 'mapInv': row['tMapInv'], 'own': d['tOwn'],
        'done': d['tDone'], 'clearPublish': row['tClearPublish'], 'retireInv': row['tRetireInv'],
        'free': d['tFree'], 'cumulative': d['cumulative'], 'doneClose': d['doneClose'],
        'closeMask': hex(d['closeMask']),
        'completionExpectedObserved': [[row[k]['expected'], row[k]['observed']] for k in ('mapCommand', 'retireCommand')]})
pairs = []
for i, old in enumerate(rows):
    for new in rows[i+1:]:
        for a in old['segments'][:old['count']]:
            for b in new['segments'][:new['count']]:
                pairs.append({'oldReq': old['req'], 'newReq': new['req'], 'exactIova': a['iova'] == b['iova'],
                    'sameIovaPage': a['iova'] // 4096 == b['iova'] // 4096,
                    'overlapBytes': max(0, min(a['iova'] + a['bytes'], b['iova'] + b['bytes']) - max(a['iova'], b['iova'])),
                    'differentPA': a['pa'] != b['pa'], 'retireBeforeRemap': old['tRetireInv'] < new['tMapPublish']})
print(json.dumps({'manifestFilesVerified': files, 'manifestErrors': errors, 'requests': summary,
                  'allPriorLaterPairs': pairs}, indent=2))
