#!/usr/bin/env python3
"""Read-only raw lifecycle dump; no file writes or producer verdicts."""
import json
from pathlib import Path
import sys
sys.dont_write_bytecode = True
import analyze as X

cap = Path(sys.argv[1])
h, rs = X.decode_domain((cap / 'r16-domain-raw.bin').read_bytes())
dh, ds = X.decode_driver((cap / 'r16-driver-raw.bin').read_bytes())
blob = (cap / 'obs-snapshot-used.bin').read_bytes()
oh = X.A.decode_header(blob)
obs = [X.A.valid_record(blob, oh, i) for i in range(oh['recordCount'])]
print(json.dumps({'domain': h, 'driver': dh, 'obs': oh}, indent=2))
for r, d in zip(rs, ds):
    print('REQUEST', r['req'])
    for i, seg in enumerate(r['segments'][:r['count']]):
        print('segment%d PA=0x%x IOVA=0x%x bytes=%d' % (i, seg['pa'], seg['iova'], seg['bytes']))
    print('physical=', [hex(n) for n in r['physical'][:r['pages']]])
    print('mapPTE=', [hex(n) for n in r['mapPte'][:r['pages']]])
    print('mapPTEextra=', [hex(n & ~X.MASK) for n in r['mapPte'][:r['pages']]])
    print('clearPTE=', r['clearPte'])
    print(json.dumps({'domain_times': {k: v for k,v in r.items() if k.startswith('t')},
          'commands': [r['mapCommand'], r['retireCommand']],
          'driver': {k:v for k,v in d.items() if not isinstance(v, list)},
          'desc': d['descriptors'][:d['count']],
          'OBS': [o for o in obs if o['token'] == r['token'] and o['reqId'] == r['req'] or
                  o['kind'] == 2 and d['cumulative'] <= o['cum'] < d['cumulative'] + d['count']]}, indent=2))
