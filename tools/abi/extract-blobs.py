import pathlib
import re
import sys

cap = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else '/Users/ling/r21-run1-20261102')
props = (cap / 'props.txt').read_text(errors='replace')
drv = (cap / 'driver-obs.txt').read_text(errors='replace')


def blob(txt, key):
    m = re.search(re.escape(key) + r'" = <([0-9a-f\s]*)>', txt)
    if not m:
        return None
    return bytes.fromhex(re.sub(r'\s', '', m.group(1)))


for key, name in (('m2-3b-domain-raw', 'r21-domain-raw.bin'),
                  ('m2-3b-pt-raw', 'r21-pt-raw.bin'),
                  ('m2-3b-driver-raw', 'r21-driver-raw.bin')):
    b = blob(props, key)
    if b:
        (cap / name).write_bytes(b)
        print(name, len(b))
    else:
        print('MISSING', key)

for key, name in (('rtl812x-txmap-std-raw', 'r21-std-raw.bin'),
                  ('rtl812x-txmap-block-raw', 'r21-block-raw.bin'),
                  ('rtl812x-txmap-raw', 'r21-driver-raw2.bin')):
    b = blob(drv, key)
    if b:
        (cap / name).write_bytes(b)
        print(name, len(b))
    else:
        print('MISSING', key)
