#!/usr/bin/env python3
"""R69 closure: record the final system state after the panic investigation."""
import datetime
import plistlib
import subprocess
from pathlib import Path

RUN = Path('/Users/ling/AMDIOMMU/runs/r69')


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True,
                          text=True).stdout.strip()


def main():
    RUN.mkdir(parents=True, exist_ok=True)
    lines = []
    add = lines.append

    add('round : 69  BLOCKED (AppleEthernetRL on the AMD IOMMU mapper)')
    add('closure_local : %s' % datetime.datetime.now().astimezone().isoformat())
    add('boottime : %s' % sh('sysctl -n kern.boottime'))
    add('running_bootargs : %s' % sh('sysctl -n kern.bootargs'))
    add('nvram_bootargs : %s' % sh('nvram boot-args').replace('\t', ' '))

    loaded = sh('kmutil showloaded --list-only | grep -E '
                '"AMDMapperProbe|AppleEthernetRL|RTL812xLucy|RealtekRTL8111"')
    add('loaded_extensions :')
    for row in loaded.splitlines():
        add('  %s' % row.strip())

    add('probe_loaded : %s' % ('yes' if 'AMDMapperProbe' in loaded else 'no'))

    panics = sorted(Path('/Library/Logs/DiagnosticReports').glob('*.panic'))
    add('panic_reports_present : %d' % len(panics))
    for item in panics[-4:]:
        add('  %s  %d B' % (item.name, item.stat().st_size))

    efi = Path('/Volumes/EFI')
    if (efi / 'EFI/OC/config.plist').is_file():
        cfg = plistlib.loads((efi / 'EFI/OC/config.plist').read_bytes())
        adds = [a.get('BundlePath') for a in cfg['Kernel']['Add']]
        args = cfg['NVRAM']['Add'][
            '7C436110-AB2A-4BBB-A880-FE41995C9F82']['boot-args']
        add('efi_mounted : yes')
        add('efi_adds : %s' % ', '.join(adds))
        add('efi_probe_injected : %s'
            % ('yes' if 'AMDMapperProbe.kext' in adds else 'no'))
        add('efi_bootargs_tail : %s' % args[-70:])
        add('efi_patch_count : %d' % len(cfg['Kernel']['Patch']))
        add('efi_aerl_patches : %d' % len([
            p for p in cfg['Kernel']['Patch']
            if (p.get('Comment') or '').startswith('laobamac | ')]))
    else:
        add('efi_mounted : no')

    add('holds :')
    for item in sorted(Path('/Users/ling/r69-hold').glob('*')):
        add('  %s' % item.name)

    add('networking : %s' % sh(
        'ifconfig en2 2>/dev/null | head -1; ifconfig en4 2>/dev/null | head -1')
        .replace('\n', ' | '))

    text = '\n'.join(lines) + '\n'
    # Python 3.9's write_text() has no newline argument; open() does.
    with open(RUN / 'closure.txt', 'w', encoding='utf-8', newline='') as handle:
        handle.write(text)
    print(text)


if __name__ == '__main__':
    main()
