#!/usr/bin/env python3
"""R66-2 PM evidence and arm checks. This tool never initiates sleep or reboot."""
import argparse
import hashlib
import json
import plistlib
import re
import runpy
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve()
ENTRY = globals().get('ROUND_ENTRY') or runpy.run_path(str(HERE.with_name('run.py')))
SHARED = ENTRY.get('SHARED') or ENTRY['R64']['previous']['shared']
C = SHARED['common']
C.select_run(ENTRY['RUN'])
SESSION = runpy.run_path(str(HERE.parents[1] / 'session/session.py'))


def read_state(config):
    tree = C.registry()
    selected = C.selected_drivers(tree, config)
    owners = [n for n, _ in C.nodes(tree) if n.get('r52-role') == 'controller']
    if len(owners) != 1:
        raise ValueError('expected exactly one shared controller')
    owner_id = owners[0]['IORegistryEntryID']
    entries = {v['binding']['driver_registry_id']: C.PROFILES[v['binding']['driver_class']]['snapshot']
               for v in selected.values()}
    entries[owner_id] = 'R52Snapshot'
    C.set_booleans(entries)
    tree = C.registry()
    owner = next(n for n, _ in C.nodes(tree) if n.get('IORegistryEntryID') == owner_id)
    selected = C.selected_drivers(tree, config)
    state = {'controller': C.C.scalars(owner, ('r52-', 'r66-', 'r66_2-')), 'devices': {}}
    for role, value in selected.items():
        requester = value['binding']['requester']
        domains = [p for p in owner.get('r52-domains', []) if p.get('r52-requester') == requester]
        if len(domains) != 1:
            raise ValueError('missing unique domain for ' + role)
        p = domains[0]
        state['devices'][role] = {
            'requester': requester,
            'driver_class': value['binding']['driver_class'],
            'driver': C.C.scalars(value['node'], ('rtl8111-', 'rtl812x-')),
            'probe': C.C.scalars(p, ('r44-', 'r47-', 'r52-', 'r63-', 'r65-', 'r66-', 'r66_2-')),
            'pm_raw_sha256': {k: hashlib.sha256(v).hexdigest() for k, v in p.items()
                              if k.startswith('r47-') and isinstance(v, bytes)}}
    return tree, state, owner_id


def need(ok, message):
    if not ok:
        raise ValueError(message)


def require_participants(state):
    c = state['controller']
    need(c['r52-controller-ready'] == 'yes' and c['r52-controller-target-faults'] == 0,
         'controller is not ready and fault-free')
    need(c['r52-domain-count'] == 2 and len(state['devices']) == 2 and
         len({v['requester'] for v in state['devices'].values()}) == 2,
         'expected two distinct requester domains')
    for role in ('a', 'b'):
        value = state['devices'][role]
        profile, driver = C.profile_for_state(value), value['driver']
        expected = 'RTL8125' if C.RUN.dual_lucy or role == 'b' else 'RTL8111'
        need(profile == C.PROFILES[expected], role + ': wrong driver for this run profile')
        if expected == 'RTL8111':
            need(driver.get('rtl8111-r66_2-pm-hooks') == 1, 'RTL8111 PM hooks are missing')
        else:
            need('rtl812x-r47-sleep-count' in driver, role + ': Lucy R47 PM hooks are missing')
        p = value['probe']
        need(driver.get(profile['prefix'] + 'state') == 'enabled' and
             p['r63-dma-parked'] == 'no' and p['r44-dte-active'] == 'yes' and
             p['r44-target-faults'] == 0, role + ': requester is not active and fault-free')


def capture(folder, config):
    tree, state, _ = read_state(config)
    state['boottime'] = subprocess.check_output(['sysctl', '-n', 'kern.boottime'], text=True).strip()
    state['boot_session_uuid'] = subprocess.check_output(
        ['sysctl', '-n', 'kern.bootsessionuuid'], text=True).strip()
    log = subprocess.check_output(['pmset', '-g', 'log'], text=True)
    counts = re.findall(r'Total Sleep/Wakes since boot[^\n]*:\s*(\d+)', log)
    state['system_sleep_wakes'] = int(counts[-1]) if counts else None
    folder.mkdir(parents=True, exist_ok=False)
    (folder / 'registry.plist').write_bytes(plistlib.dumps(tree))
    (folder / 'pmset-log.txt').write_text(log, encoding='utf-8')
    (folder / 'state.json').write_text(json.dumps(state, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps(state, indent=2, sort_keys=True))


def analyze(before, after):
    checks = []
    def check(name, action):
        try:
            action()
            checks.append({'id': name, 'ok': True})
        except (KeyError, TypeError, ValueError) as exc:
            checks.append({'id': name, 'ok': False, 'detail': str(exc)})
    def system():
        if before.get('boot_session_uuid') or after.get('boot_session_uuid'):
            need(before.get('boot_session_uuid') == after.get('boot_session_uuid'),
                 'boot session UUID changed during sleep/wake')
        # macOS re-reads the RTC at wake and nudges kern.boottime by the
        # measured drift (observed ~1s). A real reboot moves boottime to the
        # wake wall-clock, minutes later; only that magnitude proves a reboot.
        def boot_sec(text):
            m = re.search(r'sec = (\d+)', text)
            return int(m.group(1)) if m else None
        b0, b1 = boot_sec(before['boottime']), boot_sec(after['boottime'])
        need(b0 is not None and b1 is not None and abs(b1 - b0) <= 15,
             'reboot occurred instead of same-boot wake')
        w0, w1 = before['system_sleep_wakes'], after['system_sleep_wakes']
        need((w0 or 0) + 1 == w1,
             'pmset does not prove exactly one added system sleep/wake')
    check('same-boot-real-sleep-wake', system)
    def controller():
        a, b = before['devices']['a']['probe'], after['devices']['a']['probe']
        need(b['r47-suspend-count'] == a['r47-suspend-count'] + 1 and
             b['r47-resume-count'] == a['r47-resume-count'] + 1,
             'shared controller did not complete exactly one PM cycle')
        need(b['r47-pm-failures'] == 0 and b['r47-resume-registers-restored'] == 'yes',
             'controller register restoration failed')
        need(after['controller']['r52-controller-command-failed'] == 'no', 'command queue failed')
        require_participants(after)
    check('controller-restored-once', controller)
    def domain(role):
        old, new = before['devices'][role], after['devices'][role]
        a, b = old['probe'], new['probe']
        need(all(a[k] == b[k] for k in ('r52-mapper-id', 'r44-domain-id', 'r44-root-pa')),
             role + ': mapper/domain identity changed')
        need(b['r66_2-pm-suspends'] == a['r66_2-pm-suspends'] + 1 and
             b['r66_2-pm-resumes'] == a['r66_2-pm-resumes'] + 1, role + ': missing domain PM callback')
        need(before['controller']['r52-controller-cmd-completed'] < b['r66_2-pm-suspend-cw']
             <= b['r47-suspend-cw-sequence'] < b['r66_2-pm-resume-dev-cw'] and
             b['r66_2-pm-resume-pages-cw'] == b['r66_2-pm-resume-dev-cw'] + 1,
             role + ': PM completion sequence is stale or missing')
        hashes = new['pm_raw_sha256']
        for suffix in ('live-raw', 'pt-raw'):
            need(hashes['r47-suspend-' + suffix] == hashes['r47-resume-' + suffix],
                 role + ': retained mapping/PT bytes changed across the PM boundary')
        prefix = C.profile_for_state(new)['pm_prefix']
        need(C.profile_for_state(old)['pm_prefix'] == prefix, role + ': driver identity changed')
        d0, d1 = old['driver'], new['driver']
        need(d1[prefix + 'sleep-count'] == d0[prefix + 'sleep-count'] + 1 and
             d1[prefix + 'wake-count'] == d0[prefix + 'wake-count'] + 1,
             role + ': driver PM handshake incomplete')
        need(d1[prefix + 'pm-blocked'] == 0 and d1[prefix + 'last-error'] == 0,
             role + ': driver remains PM-blocked')
        times = [d1[prefix + k] for k in ('sleep-quiesced-at', 'sleep-suspended-at', 'sleep-d3-at',
                                        'wake-d0-at', 'wake-restored-at', 'wake-enable-at', 'wake-linkup-at')]
        need(all(t > 0 for t in times) and times == sorted(times), role + ': DMA restart preceded PM restoration')
    for role in ('a', 'b'):
        check(role + '-domain-and-driver-restored', lambda role=role: domain(role))
    return {'ok': all(row['ok'] for row in checks), 'checks': checks,
            'scope': 'one real PM cycle; sustained traffic is checked separately'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    for action in ('arm', 'disarm', 'capture'):
        p = sub.add_parser(action)
        p.add_argument('--config', type=Path, required=True)
        if action == 'capture':
            p.add_argument('--out', type=Path, required=True)
    p = sub.add_parser('analyze')
    p.add_argument('--before', type=Path, required=True)
    p.add_argument('--after', type=Path, required=True)
    args = parser.parse_args()
    if args.action == 'analyze':
        load = lambda p: json.loads((p / 'state.json').read_text(encoding='utf-8'))
        result = analyze(load(args.before), load(args.after))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result['ok'] else 1
    config = C.configuration(args.config)
    if args.action == 'capture':
        capture(args.out, config)
        return 0
    _, state, owner_id = read_state(config)
    if args.action == 'arm':
        require_participants(state)
        C.set_boolean(owner_id, 'R66ArmSystemPM')
    else:
        SESSION['set_boolean_property']('R66ArmSystemPM', value=False)
    _, after, _ = read_state(config)
    expected = 'yes' if args.action == 'arm' else 'no'
    need(all(d['probe']['r66-pm-armed'] == expected for d in after['devices'].values()),
         'arm-state readback differs')
    print('coordinated PM armed=' + expected)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
