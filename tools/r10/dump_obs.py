#!/usr/bin/env python3
"""Round-10 helper: extract the driver's published obs log from props.txt.

Inputs are the untouched round-9 capture files. Nothing is inferred here:
this only pulls the raw property text/blob out so later tools can decode it
independently of the probe's own summary attributes.
"""
import hashlib
import json
import re
import sys

PROPS = sys.argv[1] if len(sys.argv) > 1 else \
    'docs/evidence/20261031-172647/props.txt'

HEADER_KEYS = [
    'rtl812x-obs-format', 'rtl812x-obs-state', 'rtl812x-obs-rec-size',
    'rtl812x-obs-capacity', 'rtl812x-obs-head', 'rtl812x-obs-first',
    'rtl812x-obs-wrapped', 'rtl812x-obs-published',
    'rtl812x-obs-t-start', 'rtl812x-obs-t-published',
]


def main():
    raw = open(PROPS, 'rb').read()
    txt = raw.decode('utf-8', 'replace')
    print('props sha256 =', hashlib.sha256(raw).hexdigest())
    print('props bytes  =', len(raw))

    for key in HEADER_KEYS:
        pat = re.compile(r'"' + re.escape(key) + r'"\s*=\s*("(?:[^"]*)"|<([0-9a-fA-F]*)>)')
        m = pat.search(txt)
        if not m:
            print('%-28s = ABSENT' % key)
            continue
        if m.group(2) is not None:
            print('%-28s = <%d hex chars = %d bytes>'
                  % (key, len(m.group(2)), len(m.group(2)) // 2))
        else:
            print('%-28s = %s' % (key, m.group(1)))

    pat = re.compile(r'"rtl812x-obs-records"\s*=\s*<([0-9a-fA-F]*)>')
    m = pat.search(txt)
    if not m:
        print('rtl812x-obs-records        = ABSENT')
        return
    blob_hex = m.group(1)
    blob = bytes.fromhex(blob_hex)
    print('rtl812x-obs-records        = %d bytes, sha256=%s'
          % (len(blob), hashlib.sha256(blob).hexdigest()))
    out = {'blob_sha256': hashlib.sha256(blob).hexdigest(),
           'blob_bytes': len(blob),
           'props_sha256': hashlib.sha256(raw).hexdigest()}
    with open('docs/evidence/20261031-172647/driver-obs-blob.bin', 'wb') as f:
        f.write(blob)
    print(json.dumps(out))


if __name__ == '__main__':
    main()
