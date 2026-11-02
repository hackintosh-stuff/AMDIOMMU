#!/usr/bin/env python3
"""Print raw hardware records without substituting a correctness verdict."""
from pathlib import Path
import json
import sys
sys.dont_write_bytecode = True
import analyze as A

def main():
    cap=Path(sys.argv[1])
    h, rs=A.decode_domain((cap/'r16-domain-raw.bin').read_bytes())
    dh, ws=A.decode_driver((cap/'r16-driver-raw.bin').read_bytes())
    rows=[]
    for r,w in zip(rs,ws):
        rows.append(dict(req=r['req'],handle=r['handle'],status=r['status'],pages=r['pages'],
            segments=[dict(pa=hex(s['pa']),length=s['bytes'],offset=hex(s['pa']&4095),iova=hex(s['iova'])) for s in r['segments'][:r['count']]],
            pte=[hex(x) for x in r['mapPte'][:r['pages']]],
            clear_zero=not any(r['clearPte']),
            times_ns=dict(publish=r['tMapPublish'],map_inv=r['tMapInv'],own=w['tOwn'],completion=w['tDone'],clear=r['tClearPublish'],retire_inv=r['tRetireInv'],free=w['tFree']),
            map_command=r['mapCommand'],retire_command=r['retireCommand'],
            firstSlot=w['firstSlot'],lastSlot=w['lastSlot'],cumulative=w['cumulative'],doneClose=w['doneClose'],closeMask=hex(w['closeMask']),
            descriptors=[dict(address=hex(d['address']),length=d['length'],opts1=hex(d['opts1']),opts2=hex(d['opts2'])) for d in w['descriptors'][:w['count']]]))
    print(json.dumps(dict(domain=h,driver=dh,requests=rows),indent=2))
if __name__=='__main__': main()
