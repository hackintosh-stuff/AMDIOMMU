#!/usr/bin/env python3
from pathlib import Path
import hashlib, json, runpy, sys
ROOT=Path(__file__).resolve().parents[2]
TEMPLATE=Path(__file__).with_name('driver-template.py')
VERSION='1.1.241'
def sha(data): return hashlib.sha256(data).hexdigest()
def main():
    if len(sys.argv)!=2: raise SystemExit('usage: apply-lucy.py <relative-lucy-input>')
    source=(ROOT/sys.argv[1]).resolve(); source.relative_to(ROOT)
    drv=source/'RTL812xLucy'; cpp=drv/'RTL812xLucy.cpp'; hpp=drv/'RTL812xLucy.hpp'
    stamp=source/'.r64-generated.json'
    if not cpp.is_file() or not hpp.is_file(): raise SystemExit('R64 Lucy input incomplete')
    if '#define kRxMemBaseShift 7' not in hpp.read_text(errors='replace'):
        raise SystemExit('R64 requires 8 x 128-page RX grouping')
    mod=runpy.run_path(str(TEMPLATE)); text=cpp.read_text(encoding='utf-8')
    fingerprint=sha(TEMPLATE.read_bytes())
    if stamp.is_file():
        record=json.loads(stamp.read_text())
        if record.get('version')!=VERSION or record.get('template')!=fingerprint or not mod['is_current'](text):
            raise SystemExit('R64 generated Lucy input stale or modified')
        print('R64 Lucy lifecycle already current'); return
    if 'RequestPowerTransition' not in text or 'r44NormalMapped' not in text:
        raise SystemExit('R64 requires the ordinary mapped Lucy base')
    updated=mod['patch'](text); cpp.write_bytes(updated.encode('utf-8'))
    record={'version':VERSION,'template':fingerprint,'input_cpp_sha256':sha(text.encode()),'output_cpp_sha256':sha(updated.encode())}
    stamp.write_bytes((json.dumps(record,indent=2)+chr(10)).encode('utf-8'))
    print('R64 requester park/restore applied')
if __name__=='__main__': main()
