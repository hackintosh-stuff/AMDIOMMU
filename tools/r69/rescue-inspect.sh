#!/bin/sh
# R69 rescue-side inspection: mount the SATA ESP read-write only for the
# config edit, and copy the panic report out of the APFS container read-only.
set -eu
ESP=/dev/sda1
W=/root/r69

mkdir -p "$W"
echo "== identity =="
hostname
date -u +%Y-%m-%dT%H:%M:%SZ

echo "== mounting ESP $ESP =="
mkdir -p /mnt/esp
mountpoint -q /mnt/esp || mount "$ESP" /mnt/esp
ls -l /mnt/esp/EFI/OC/config.plist
sha256sum /mnt/esp/EFI/OC/config.plist

echo "== current boot args and injection list =="
python3 - <<'PY'
import plistlib
p = '/mnt/esp/EFI/OC/config.plist'
cfg = plistlib.load(open(p, 'rb'))
ba = cfg['NVRAM']['Add']['7C436110-AB2A-4BBB-A880-FE41995C9F82']['boot-args']
print('boot-args:', ba)
print('Add entries:')
for a in cfg['Kernel']['Add']:
    print('   %-32s enabled=%s' % (a.get('BundlePath'), a.get('Enabled')))
print('patches: %d total, %d for AppleEthernetRL' % (
    len(cfg['Kernel']['Patch']),
    len([x for x in cfg['Kernel']['Patch']
         if (x.get('Comment') or '').startswith('laobamac | ')])))
PY

echo "== probe kext present in ESP? =="
ls -d /mnt/esp/EFI/OC/Kexts/AMDMapperProbe.kext 2>/dev/null || echo "absent"
