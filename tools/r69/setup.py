#!/usr/bin/env python3
"""R69: install the SimpleAERL v1.1 AppleEthernetRL patches and the R69 boot args.

Why a separate tool: AppleEthernetRL is a system kext, so it cannot be rebuilt
locally. The vendor patch set (Kernel > Patch, symbol based) is the only way to
let it drive a generic RTL8125/8126/8127. This tool only edits the OpenCore
config; it never touches a kext, the kernel collection or a disk.

Usage (on the Mac, with the EFI mounted):
    python3 tools/r69/setup.py apply  --efi /Volumes/EFI --plist ~/r69/AERL.plist \
        --args 'amdiommu=auto amdiommu_devices=2200,2500 amdiommu_autoattach=1'
    python3 tools/r69/setup.py status --efi /Volumes/EFI
    python3 tools/r69/setup.py remove --efi /Volumes/EFI --args 'amdiommu=off'
"""
import argparse
import datetime
import plistlib
import shutil
import subprocess
import sys
from pathlib import Path

IDENTIFIER = 'com.apple.driver.AppleEthernetRL'
BOOT_KEYS = ('amdiommu=', 'amdiommu_devices=', 'amdiommu_autoattach=')
NVRAM_GUID = '7C436110-AB2A-4BBB-A880-FE41995C9F82'


def config_path(efi):
    path = Path(efi) / 'EFI/OC/config.plist'
    if not path.is_file():
        raise SystemExit('FAIL: no OpenCore config at %s' % path)
    return path


def load(path):
    return plistlib.loads(path.read_bytes())


def vendor_patches(plist_path):
    entries = plistlib.loads(Path(plist_path).read_bytes())
    kernel = entries.get('Kernel') or entries.get('KernelAndKextPatches') or {}
    patches = kernel.get('Patch') or []
    if not patches:
        raise SystemExit('FAIL: %s carries no Kernel > Patch entries' % plist_path)
    for patch in patches:
        if patch.get('Identifier') != IDENTIFIER:
            raise SystemExit('FAIL: patch targets %r, expected %r'
                             % (patch.get('Identifier'), IDENTIFIER))
        for key in ('Find', 'Replace'):
            if not patch.get(key):
                raise SystemExit('FAIL: patch %r has an empty %s'
                                 % (patch.get('Comment'), key))
        find, replace = patch['Find'], patch['Replace']
        if len(find) != len(replace):
            raise SystemExit('FAIL: %r length differs (%d vs %d)'
                             % (patch.get('Comment'), len(find), len(replace)))
        mask = patch.get('Mask') or b''
        if mask and len(mask) != len(find):
            raise SystemExit('FAIL: %r mask length %d != find %d'
                             % (patch.get('Comment'), len(mask), len(find)))
    return patches


def is_ours(entry):
    return (entry.get('Identifier') == IDENTIFIER
            and (entry.get('Comment') or '').startswith('laobamac | '))


def desired_patches(cfg, patches):
    kernel = cfg.setdefault('Kernel', {})
    current = kernel.get('Patch') or []
    kept = [p for p in current if not is_ours(p)]
    removed = len(current) - len(kept)
    kernel['Patch'] = kept + patches
    return len(cfg['Kernel']['Patch']), removed


def boot_args(cfg):
    nvram = cfg.setdefault('NVRAM', {}).setdefault('Add', {}).setdefault(
        NVRAM_GUID, {})
    return nvram.get('boot-args', '')


def set_boot_args(cfg, args):
    tokens = [t for t in boot_args(cfg).split()
              if not t.startswith(BOOT_KEYS)]
    tokens.extend(t for t in args.split() if t)
    nvram = cfg.setdefault('NVRAM', {}).setdefault('Add', {}).setdefault(
        NVRAM_GUID, {})
    nvram['boot-args'] = ' '.join(tokens)
    return nvram['boot-args']


def backup(path):
    stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    target = path.with_name('%s.bak_r69_%s' % (path.name, stamp))
    shutil.copy2(path, target)
    return target


def write_verified(path, cfg):
    tmp = path.with_name(path.name + '.r69tmp')
    tmp.write_bytes(plistlib.dumps(cfg, sort_keys=False))
    subprocess.run(['plutil', '-lint', str(tmp)], check=True,
                   stdout=subprocess.DEVNULL)
    back = plistlib.loads(tmp.read_bytes())
    if back != cfg:
        raise SystemExit('FAIL: config read-back differs from what was written')
    shutil.move(str(tmp), str(path))
    return plistlib.loads(path.read_bytes())


def summarize(cfg):
    kernel = cfg.get('Kernel', {})
    ours = [p for p in (kernel.get('Patch') or []) if is_ours(p)]
    print('  AppleEthernetRL patches: %d' % len(ours))
    for patch in ours:
        print('    %-58s base=%s' % ((patch.get('Comment') or '')[:58],
                                     (patch.get('Base') or '-')[:40]))
    print('  boot-args: %s' % boot_args(cfg))


def injection_entry(bundle, name):
    info = plistlib.loads((Path(bundle) / 'Contents/Info.plist').read_bytes())
    executable = info.get('CFBundleExecutable')
    if not executable:
        raise SystemExit('FAIL: %s has no CFBundleExecutable' % bundle)
    return {
        'Arch': 'Any',
        'BundlePath': name,
        'Comment': 'R69 IOMapper probe for third-party clients',
        'Enabled': True,
        'ExecutablePath': 'Contents/MacOS/%s' % executable,
        'MaxKernel': '',
        'MinKernel': '',
        'PlistPath': 'Contents/Info.plist',
    }


def upsert_injection(cfg, entry):
    kernel = cfg.setdefault('Kernel', {})
    adds = kernel.get('Add') or []
    kept = [a for a in adds if a.get('BundlePath') != entry['BundlePath']]
    kernel['Add'] = kept + [entry]
    return len(kernel['Add'])


def drop_injection(cfg, name):
    kernel = cfg.setdefault('Kernel', {})
    adds = kernel.get('Add') or []
    kernel['Add'] = [a for a in adds if a.get('BundlePath') != name]
    return len(adds) - len(kernel['Add'])



def main(argv):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='cmd', required=True)
    for name in ('apply', 'remove'):
        item = sub.add_parser(name)
        item.add_argument('--efi', required=True)
        item.add_argument('--plist')
        item.add_argument('--args', default='')
        item.add_argument('--check-only', action='store_true')
    status = sub.add_parser('status')
    status.add_argument('--efi', required=True)
    inject = sub.add_parser('inject')
    inject.add_argument('--efi', required=True)
    inject.add_argument('--kext', required=True)
    inject.add_argument('--name', default='AMDMapperProbe.kext')
    inject.add_argument('--check-only', action='store_true')
    eject = sub.add_parser('eject')
    eject.add_argument('--efi', required=True)
    eject.add_argument('--name', default='AMDMapperProbe.kext')
    eject.add_argument('--check-only', action='store_true')
    args = parser.parse_args(argv)

    path = config_path(args.efi)
    cfg = load(path)

    if args.cmd == 'status':
        summarize(cfg)
        return 0

    if args.cmd == 'inject':
        entry = injection_entry(args.kext, args.name)
        total = upsert_injection(cfg, entry)
        print('would inject %s (%s), %d Add entries'
              % (args.name, entry['ExecutablePath'], total))
        if args.check_only:
            return 0
        dest = Path(args.efi) / 'EFI/OC/Kexts' / args.name
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(args.kext, dest)
        subprocess.run(['codesign', '--verify', '--strict', str(dest)],
                       check=True)
        saved = backup(path)
        write_verified(path, cfg)
        print('injected %s (signature verified); backup %s' % (dest, saved))
        return 0

    if args.cmd == 'eject':
        removed = drop_injection(cfg, args.name)
        print('would remove %d Add entries for %s' % (removed, args.name))
        if args.check_only:
            return 0
        saved = backup(path)
        write_verified(path, cfg)
        print('ejected; backup %s' % saved)
        return 0

    if args.cmd == 'apply':
        if not args.plist:
            raise SystemExit('FAIL: apply needs --plist')
        patches = vendor_patches(args.plist)
        total, removed = desired_patches(cfg, patches)
        wanted = set_boot_args(cfg, args.args) if args.args else boot_args(cfg)
        print('would write %d patches (%d replaced), boot-args: %s'
              % (len(patches), removed, wanted))
        if args.check_only:
            return 0
        saved = backup(path)
        print('backup: %s' % saved)
        back = write_verified(path, cfg)
        print('verified: %d total patches, %d for AppleEthernetRL'
              % (len(back['Kernel']['Patch']),
                 len([p for p in back['Kernel']['Patch'] if is_ours(p)])))
        nvram_args = back['NVRAM']['Add'][NVRAM_GUID]['boot-args']
        if nvram_args != wanted:
            raise SystemExit('FAIL: boot-args read-back %r != %r'
                             % (nvram_args, wanted))
        print('verified boot-args: %s' % nvram_args)
        return 0

    if args.cmd == 'remove':
        kernel = cfg.setdefault('Kernel', {})
        current = kernel.get('Patch') or []
        kernel['Patch'] = [p for p in current if not is_ours(p)]
        print('removed %d AppleEthernetRL patches' % (len(current) - len(kernel['Patch'])))
        wanted = set_boot_args(cfg, args.args) if args.args else boot_args(cfg)
        print('boot-args: %s' % wanted)
        if args.check_only:
            return 0
        saved = backup(path)
        print('backup: %s' % saved)
        write_verified(path, cfg)
        return 0

    raise SystemExit('unknown command')


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
