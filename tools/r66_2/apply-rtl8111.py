#!/usr/bin/env python3
"""Upgrade the existing R63 RTL8111 input in place; never clone or copy it."""
from pathlib import Path
import hashlib
import json
import plistlib
import runpy
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = Path(__file__).with_name('driver-template.py')
BASE = ROOT / 'tools/r63/apply-rtl8111.py'
VERSION = '3.0.56'
DEPENDENCY = '0.74.0'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def upgraded(files):
    model = runpy.run_path(str(TEMPLATE))
    names = ('RealtekRTL8111.hpp', 'RealtekRTL8111.cpp', 'RealtekRTL8111Hardware.cpp')
    result = dict(zip(names, (x.encode('utf-8') for x in model['patch'](
        *(files[n].decode('utf-8') for n in names)))))
    info = plistlib.loads(files['Info.plist'])
    info['CFBundleVersion'] = info['CFBundleShortVersionString'] = VERSION
    info['IOKitPersonalities']['RTL8111 PCIe Adapter']['DriverVersion'] = VERSION
    info['OSBundleLibraries']['org.maz1.AMDMapperProbe'] = DEPENDENCY
    result['Info.plist'] = plistlib.dumps(info, sort_keys=False)
    return result


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: apply-rtl8111.py <existing-rtl8111-input>')
    source = Path(sys.argv[1]).resolve()
    source.relative_to(ROOT)
    stamp = source / '.r53-generated.json'
    fingerprint = digest(Path(__file__).read_bytes() + TEMPLATE.read_bytes() + BASE.read_bytes())
    old = json.loads(stamp.read_bytes()) if stamp.exists() else {}
    if old.get('version') == VERSION:
        if old.get('generator') != fingerprint or any(
                digest((source / name).read_bytes()) != value
                for name, value in old['files'].items()):
            raise SystemExit('R66-2 generated input changed; reconcile in place')
        print('RTL8111 R66-2 input already current')
        return
    subprocess.run([sys.executable, '-B', str(BASE), str(source)], check=True)
    old = json.loads(stamp.read_bytes())
    if old['version'] != '3.0.55':
        raise SystemExit('R63 generated RTL8111 input required')
    driver = source / 'RealtekRTL8111'
    names = ('RealtekRTL8111.hpp', 'RealtekRTL8111.cpp', 'RealtekRTL8111Hardware.cpp', 'Info.plist')
    result = upgraded({n: (driver / n).read_bytes() for n in names})
    for name, data in result.items():
        (driver / name).write_bytes(data)
        old['files']['RealtekRTL8111/' + name] = digest(data)
    old.update(version=VERSION, generator=fingerprint)
    stamp.write_bytes((json.dumps(old, indent=2) + '\n').encode('utf-8'))
    print('RTL8111 3.0.56: PM participant and mapped recovery path generated')


if __name__ == '__main__':
    main()
