#!/usr/bin/env python3
"""Select only the two Lucy requesters; retain binaries and their true provenance.

select-next changes only two boot arguments, never kexts/AuxKC or the live
controller. No command in this module reboots or triggers system sleep.
"""
import argparse
import json
from pathlib import Path
import plistlib
import runpy
import shutil
import subprocess

HERE = Path(__file__).resolve()
ENTRY = globals().get('ROUND_ENTRY') or runpy.run_path(str(HERE.with_name('run.py')))
C = ENTRY['SHARED']['common']
C.select_run(ENTRY['RUN'])
W = runpy.run_path(str(HERE.parents[0] / 'postwake/postwake.py'), init_globals={'ROUND_ENTRY': ENTRY})
C.select_run(ENTRY['RUN'])
need, read, write = W['need'], W['read'], W['write']


def inventory():
    result = []
    for node, parents in C.nodes(C.registry()):
        if node.get('IOObjectClass', node.get('IOClass')) != 'RTL8125':
            continue
        pci = next((p for p in reversed(parents) if 'pcidebug' in p), None)
        if pci is None or C.pci_number(pci, 'device-id') != 0x8127:
            continue
        interfaces = sorted({C.C.bsd_name(n) for n, _ in C.nodes(node) if C.C.bsd_name(n)})
        requester = C.pci_requester(pci)
        if requester is None:
            continue
        result.append(dict(driver_class='RTL8125', vendor_id='%04x' % C.pci_number(pci, 'vendor-id'),
            device_id='8127', bdf='%02x:%02x.%x' % (requester >> 8, (requester >> 3) & 31, requester & 7),
            requester=requester, interfaces=interfaces, registry_id=node['IORegistryEntryID'],
            policy=pci.get('amdiommu-dma-policy', 'unpublished')))
    print(json.dumps(result, indent=2))


def inspect(config):
    drivers = C.selected_drivers(C.registry(), config)
    for endpoint in C.roles(config).values():
        W['N'].network(endpoint, wait=20)
    management = config.get('management', {})
    need(management.get('interface') and management.get('address'), 'independent management is required')
    print(json.dumps(dict(selector=C.selector(config), endpoints={r: d['binding'] for r, d in drivers.items()},
                          management=management), indent=2))


def select_next(args, config):
    # Setting next boot off must remain possible even after a failed NIC test.
    if args.mode == 'auto':
        inspect(config)
    # Reuse only the existing EFI resolver and command runner, not mixed-device deploy.
    D = C.module('_r67_2_boot_helpers', 'tools/base/deploy.py')
    path, _, _ = D.require_efi(args.efi)
    raw = path.read_bytes()
    cfg = plistlib.loads(raw)
    nvram = D.output('nvram', 'boot-args').split(None, 1)[1].strip()
    previous = cfg['NVRAM']['Add'][D.NVRAM_GUID]['boot-args']
    need(previous.split() == nvram.split(), 'EFI/NVRAM boot arguments differ before selection')
    kept = [arg for arg in nvram.split() if not arg.startswith(('amdiommu=', 'amdiommu_devices='))]
    wanted = ' '.join(kept + ['amdiommu=' + args.mode, 'amdiommu_devices=' + C.selector(config)])
    record = C.project_path(args.record)
    record.mkdir(parents=True, exist_ok=False)
    (record / 'efi-config-before.plist').write_bytes(raw)
    write(record / 'selection.json', dict(previous_boot_args=nvram, next_boot_args=wanted,
          config=config, live_kernel_changed=False, kexts_replaced=[], auxkc_rebuilt=False))
    D.run(['sudo', '-n', 'true'])
    cfg['NVRAM']['Add'][D.NVRAM_GUID]['boot-args'] = wanted
    temp = path.with_name(path.name + '.r67-2.tmp')
    try:
        temp.write_bytes(plistlib.dumps(cfg, sort_keys=False))
        D.run(['plutil', '-lint', temp])
        temp.replace(path)
        D.run(['sudo', '-n', 'nvram', 'boot-args=' + wanted])
        need(D.output('nvram', 'boot-args').split(None, 1)[1].strip() == wanted and
             plistlib.loads(path.read_bytes())['NVRAM']['Add'][D.NVRAM_GUID]['boot-args'] == wanted,
             'next-boot selection failed readback')
    except Exception:
        path.write_bytes(raw)
        subprocess.run(['sudo', '-n', 'nvram', 'boot-args=' + nvram], check=False)
        raise
    finally:
        if temp.exists():
            temp.unlink()
    print('R67-2 next-boot selection recorded; no reboot or live domain change was performed.')


def adopt(args, config):
    """Seed a fresh baseline load directory without relabeling old binaries."""
    C.boot_mode('auto')
    _, state, _ = W['PM']['read_state'](config)
    W['PM']['require_participants'](state)
    need(all(v['probe']['r66-pm-armed'] == 'no' for v in state['devices'].values()),
         'baseline must start with PM disarmed')
    origin = C.project_path(args.origin)
    source, expected = read(origin / 'source-ref.json'), read(origin / 'expected-version.json')
    need(source['base_commit'] == ENTRY['RUN'].base_commit, 'retained binary lineage differs')
    out = C.project_path(args.out)
    out.mkdir(parents=True, exist_ok=False)
    W['runtime_identity'](out / 'identity', expected)
    # These files retain the actual R66-2 build identity. Only topology is new.
    for name in ('source-ref.json', 'expected-version.json'):
        shutil.copyfile(origin / name, out / name)
    shutil.copyfile(origin / 'deployment.json', out / 'binary-deployment-origin.json')
    write(out / 'deployment.json', dict(round=67, label='R67-2', topology_only=True,
          config=config, requester_selector=C.selector(config), source_commit=source['commit'],
          base_commit=source['base_commit'], tool_commit=subprocess.check_output(
              ['git', '-C', str(C.ROOT), 'rev-parse', 'HEAD'], text=True).strip(),
          retained_bundles=list(ENTRY['RUN'].versions), replaced_bundles=[], auxkc_rebuilt=False,
          expected={name: expected[name] for name in ENTRY['RUN'].versions}))
    print('R67-2 baseline metadata ready; both retained binaries match the original artifacts.')


def main(action):
    parser = argparse.ArgumentParser(description=__doc__)
    if action != 'inventory':
        parser.add_argument('--config', required=True)
    if action == 'select-next':
        parser.add_argument('--efi', required=True)
        parser.add_argument('--record', required=True)
        parser.add_argument('--mode', choices=('auto', 'off'), default='auto')
    if action == 'adopt':
        parser.add_argument('--origin', required=True)
        parser.add_argument('--out', required=True)
    args = parser.parse_args()
    try:
        if action == 'inventory':
            inventory()
        else:
            config = C.configuration(C.project_path(args.config))
            if action == 'inspect': inspect(config)
            elif action == 'select-next': select_next(args, config)
            else: adopt(args, config)
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print('R67-2 setup failed:', exc)
        return 1


if __name__ == '__main__':
    raise SystemExit('Use tools/run.py {inventory,inspect,select-next,adopt}')
