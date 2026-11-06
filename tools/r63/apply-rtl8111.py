#!/usr/bin/env python3
"""Upgrade the original, validated R54 input in place; do not create a checkout."""
from pathlib import Path
import hashlib
import json
import plistlib
import subprocess
import sys

VERSION = '3.0.55'
ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'tools/r53/apply-rtl8111.py'


def upgraded(cpp, info):
    def once(src, old, new):
        if src.count(old) != 1:
            raise ValueError('unexpected R54 driver anchor: ' + old[:60])
        return src.replace(old, new, 1)

    anchor = 'IOReturn RTL8111::enable(IONetworkInterface *netif)'
    cpp = once(cpp, anchor, '''static IOReturn r63RequesterDMA(IOMapper *mapper, IOPCIDevice *pci, UInt32 op)
{
    if (!mapper || !pci) return kIOReturnNotReady;
    const OSSymbol *key = OSSymbol::withCString("R63SetRequesterDMA");
    if (!key) return kIOReturnNoMemory;
    const IOReturn rc = mapper->callPlatformFunction(key, false, pci,
        (void *)(uintptr_t)op, NULL, NULL);
    key->release();
    return rc;
}

''' + anchor)
    cpp = once(cpp, '    pciDevice->open(this);\n    \n    selectedMedium = getSelectedMedium();',
               '''    if (!pciDevice->open(this)) goto done;
    if (r53NormalMapped) {
        result = r63RequesterDMA(mapper, pciDevice, 2);
        if (result != kIOReturnSuccess) {
            pciDevice->close(this);
            goto done;
        }
    }
    selectedMedium = getSelectedMedium();''')
    anchor = '    clearDescriptors();\n    ++r53DisableCount;'
    cpp = once(cpp, anchor, '''    clearDescriptors();
    if (r53NormalMapped) result = r63RequesterDMA(mapper, pciDevice, 1);
    ++r53DisableCount;''')
    pl = plistlib.loads(info)
    pl['CFBundleVersion'] = pl['CFBundleShortVersionString'] = VERSION
    pl['IOKitPersonalities']['RTL8111 PCIe Adapter']['DriverVersion'] = VERSION
    pl['OSBundleLibraries']['org.maz1.AMDMapperProbe'] = '0.70.0'
    return cpp.encode(), plistlib.dumps(pl, sort_keys=False)


def main():
    source = Path(sys.argv[1]).resolve()
    source.relative_to(ROOT)
    stamp = source / '.r53-generated.json'
    old = json.loads(stamp.read_bytes()) if stamp.is_file() else {}
    digest = lambda data: hashlib.sha256(data).hexdigest()
    fingerprint = digest(Path(__file__).read_bytes() + BASE.read_bytes())
    if old.get('version') == VERSION:
        if (old.get('generator') != fingerprint or any(
                digest((source / k).read_bytes()) != v for k,v in old['files'].items())):
            raise SystemExit('R63 fixed input changed')
        return
    subprocess.run([sys.executable, '-B', str(BASE), str(source)], check=True)
    old = json.loads(stamp.read_bytes())
    if old['version'] != '3.0.54':
        raise SystemExit('R54 RTL8111 input required')
    cpp, info = ('RealtekRTL8111/' + name for name in ('RealtekRTL8111.cpp', 'Info.plist'))
    changes = upgraded((source / cpp).read_text(encoding='utf-8'), (source / info).read_bytes())
    for name, data in zip((cpp, info), changes):
        (source / name).write_bytes(data)
        old['files'][name] = digest(data)
    old.update(version=VERSION, generator=fingerprint)
    stamp.write_bytes((json.dumps(old, indent=2) + '\n').encode())


if __name__ == '__main__':
    main()
