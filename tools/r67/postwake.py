#!/usr/bin/env python3
"""Attach to an accepted live wake, exercise traffic, and retain verifiable evidence.

No kext is rebuilt or deployed. No power state, interface, or boot argument is
changed by prepare/sustain/finish. The separate native load performs the one
explicit down/up cycle per interface.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import datetime
import hashlib
import json
from pathlib import Path
import plistlib
import re
import runpy
import shutil
import socket
import subprocess
import threading
import time

HERE = Path(__file__).resolve()
ENTRY = globals().get('ROUND_ENTRY') or runpy.run_path(str(HERE.with_name('run.py')))
SCOPE = ENTRY.get('SCOPE', 'r67-postwake')
LABEL = ENTRY.get('LABEL', 'R67')
IDENTITY_SCOPE = ENTRY.get('IDENTITY_SCOPE', 'r67')
C = ENTRY['SHARED']['common']
PM = runpy.run_path(str(HERE.parents[1] / 'r66_2/pm.py'),
                    init_globals={'ROUND_ENTRY': ENTRY})
C.select_run(ENTRY['RUN'])
T = runpy.run_path(str(HERE.with_name('transport.py')))
N = C.module('_r67_network', 'tools/r52/network.py')
need = PM['need']


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def write(path, value):
    path.write_bytes((json.dumps(value, indent=2, sort_keys=True) + '\n').encode('utf-8'))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def assert_same_wake(reference, current):
    """Tie new traffic to the accepted restored domains, not to a fresh boot."""
    PM['require_participants'](current)
    def boot_sec(value):
        match = re.search(r'sec = (\d+)', value)
        need(match is not None, 'missing boottime')
        return int(match.group(1))
    need(abs(boot_sec(reference['boottime']) - boot_sec(current['boottime'])) <= 15,
         'current kernel does not belong to the recorded wake')
    need(reference['system_sleep_wakes'] == current['system_sleep_wakes'] >= 1,
         'another sleep or reboot separates the evidence')
    if reference.get('boot_session_uuid'):
        need(reference['boot_session_uuid'] == current.get('boot_session_uuid'),
             'boot session UUID changed')
    identities = ('r52-mapper-id', 'r52-owner-id', 'r44-domain-id', 'r44-root-pa',
                  'r44-controller-ready-time', 'r44-dte-active-time',
                  'r47-suspend-count', 'r47-resume-count', 'r47-resume-at',
                  'r66_2-pm-suspends', 'r66_2-pm-resumes',
                  'r66_2-pm-suspend-cw', 'r66_2-pm-resume-dev-cw', 'r66_2-pm-resume-pages-cw')
    for role in ('a', 'b'):
        old, new = reference['devices'][role], current['devices'][role]
        p, q = old['probe'], new['probe']
        need(old['requester'] == new['requester'] and all(p[k] == q[k] for k in identities),
             role + ': restored domain identity/PM generation changed')
        need(q['r66_2-pm-suspends'] == q['r66_2-pm-resumes'] >= 1 and
             q['r47-pm-failures'] == 0 and q['r47-resume-registers-restored'] == 'yes' and
             q['r44-command-failed'] == q['r44-event-overflow'] == 'no' and
             q['r44-map-rejected'] == q['r44-unmap-rejected'] == 0,
             role + ': failed PM/mapping/command state')
        for suffix in ('live-raw', 'pt-raw'):
            key = 'r47-resume-' + suffix
            need(old['pm_raw_sha256'][key] == new['pm_raw_sha256'][key],
                 role + ': retained PM boundary was replaced')
        prefix = C.profile_for_state(new)['pm_prefix']
        driver = new['driver']
        need(driver[prefix + 'pm-blocked'] == driver[prefix + 'last-error'] == 0,
             role + ': driver PM blocked')
        for k in ('sleep-count', 'wake-count', 'wake-restored-at'):
            need(driver[prefix + k] == old['driver'][prefix + k], role + ': driver PM generation changed')
    for value in current['devices'].values():
        if C.profile_for_state(value)['pm_prefix'] == 'rtl8111-r66_2-':
            need(value['driver']['rtl8111-r66_2-restart-error'] == 0,
                 'RTL8111 watchdog restart failed')
    for key in ('r52-controller-cmd-completed', 'r52-controller-cmd-wraps'):
        need(current['controller'][key] >= reference['controller'][key], 'controller counters regressed')


def checkpoint(folder, config):
    folder.mkdir(parents=True, exist_ok=False)
    # Existing snapshot code waits for native TX retirement and exports raw PTEs.
    C.snapshot(folder, 'dma', config, 'auto')
    tree, state, _ = PM['read_state'](config)
    state['boottime'] = subprocess.check_output(['sysctl', '-n', 'kern.boottime'], text=True).strip()
    state['boot_session_uuid'] = subprocess.check_output(
        ['sysctl', '-n', 'kern.bootsessionuuid'], text=True).strip()
    need(bool(state['boot_session_uuid']), 'missing boot session UUID')
    log = subprocess.check_output(['pmset', '-g', 'log'], text=True)
    counts = re.findall(r'Total Sleep/Wakes since boot[^\n]*:\s*(\d+)', log)
    state['system_sleep_wakes'] = int(counts[-1]) if counts else None
    state['monotonic_ns'] = time.monotonic_ns()
    (folder / 'registry.plist').write_bytes(plistlib.dumps(tree))
    (folder / 'pmset-log.txt').write_text(log, encoding='utf-8')
    write(folder / 'state.json', state)
    return state


def runtime_identity(folder, expected):
    folder.mkdir(parents=True, exist_ok=False)
    helper = C.module('_r67_identity', 'tools/r27/capture.py')
    got = helper.collect_system(folder, datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                ENTRY['RUN'].versions, IDENTITY_SCOPE)
    loaded = (folder / (IDENTITY_SCOPE + '-version-confirmation.txt')).read_text(encoding='utf-8').lower()
    for name, version in ENTRY['RUN'].versions.items():
        need(got[name]['version'] == version and got[name]['codesign_returncode'] == 0 and
             all(got[name][k] == expected[name][k] for k in ('version', 'uuid', 'sha256')) and
             got[name]['uuid'].lower() in loaded, 'installed/loaded kext differs: ' + name)
    write(folder / 'installed.json', got)
    return got


def prepare(args):
    config = C.configuration(C.project_path(args.config))
    before, after = C.project_path(args.pm_before), C.project_path(args.pm_after)
    accepted = C.project_path(args.accepted_capture)
    result = PM['analyze'](read(before / 'state.json'), read(after / 'state.json'))
    need(result['ok'], 'supplied PM evidence did not pass the R66-2 analyzer')
    source, expected = read(accepted / 'source-ref.json'), read(accepted / 'expected-version.json')
    need(source['base_commit'] == ENTRY['RUN'].base_commit, 'binary source lineage differs')
    out = C.project_path(args.out)
    out.mkdir(parents=True, exist_ok=False)
    write(out / 'endpoints.json', config)
    provenance = out / 'provenance'
    provenance.mkdir()
    for label, src in [('pm-before', before), ('pm-after', after)]:
        (provenance / label).mkdir()
        for name in ('state.json', 'registry.plist', 'pmset-log.txt'):
            shutil.copyfile(src / name, provenance / label / name)
    for name in ('source-ref.json', 'expected-version.json', 'deployment.json'):
        shutil.copyfile(accepted / name, provenance / name)
    runtime_identity(out / 'identity-start', expected)
    current = checkpoint(out / 'attached', config)
    assert_same_wake(read(after / 'state.json'), current)
    need(all(v['probe']['r66-pm-armed'] == 'no' for v in current['devices'].values()),
         'disarm PM before continuing traffic; do not request another sleep')
    # Keep binary provenance unchanged. This is not an R67 kext deployment.
    native = out / 'lifecycle'
    native.mkdir()
    for name in ('source-ref.json', 'expected-version.json', 'deployment.json'):
        shutil.copyfile(provenance / name, native / name)
    write(out / 'binding.json', dict(scope=SCOPE, kernel_rebuilt=False,
          tool_commit=subprocess.check_output(['git', '-C', str(C.ROOT), 'rev-parse', 'HEAD'], text=True).strip(),
          binary_source=source, token=ENTRY['RUN'].token,
          origin_sha256={label: sha(provenance / label / 'state.json') for label in ('pm-before', 'pm-after')}))
    print(LABEL + ' attached to the accepted wake; no build/deploy/reboot/sleep was performed.')


def sustain(args):
    need(300 <= args.seconds <= 600, 'use one bounded 300-600 second traffic window')
    out = C.project_path(args.out)
    binding = read(out / 'binding.json')
    config = C.configuration(out / 'endpoints.json')
    endpoints = C.roles(config)
    before = checkpoint(out / 'steady-before', config)
    assert_same_wake(read(out / 'attached/state.json'), before)
    steady = out / 'steady'
    steady.mkdir(exist_ok=False)
    file, emit = T['journal'](steady / 'client.log')
    barrier = threading.Barrier(4)

    def worker(role, direction):
        try:
            endpoint = endpoints[role]
            local, peer, index = N.network(endpoint, wait=20)
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as conn:
                conn.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                conn.settimeout(60)
                N.bind_interface(conn, index)
                conn.bind(local)
                conn.connect(peer)
                T['client_stream'](conn, role, direction, binding['token'], args.seconds,
                    barrier, emit, dict(interface=endpoint['interface'], ifindex=index,
                                        bound_ifindex=index, requester=endpoint['requester']))
        except BaseException:
            barrier.abort()
            raise

    ok = False
    try:
        emit(dict(event='start', token=binding['token'], seconds=args.seconds, streams=4))
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(worker, role, direction)
                       for role in ('a', 'b') for direction in T['DIRECTIONS']]
            for future in futures:
                future.result()
        emit(dict(event='result', ok=True))
        ok = True
    except (OSError, ValueError, RuntimeError) as exc:
        emit(dict(event='result', ok=False, error=str(exc)))
    finally:
        file.close()
        after = checkpoint(out / 'steady-after', config)
        assert_same_wake(before, after)
    need(ok, 'sustained transfer failed; preserve evidence and do not retry this output')
    print('Sustained transfer completed. Preserve both peer logs, then run the native lifecycle workload.')


def finish(args):
    out = C.project_path(args.out)
    config = C.configuration(out / 'endpoints.json')
    # Analysis outputs are regenerated here; a previous finish attempt must
    # not leave a stale copy for the manifest to seal against.
    for stale in ('analysis.json', 'analysis-recomputed.json'):
        stale_file = out / stale
        if stale_file.exists():
            stale_file.unlink()
    for role, value in [('a', args.peer_a_log), ('b', args.peer_b_log)]:
        target = out / 'steady' / ('peer-' + role + '.log')
        source = C.project_path(value)
        if source != target:
            need(not target.exists(), 'peer log already archived')
            shutil.copyfile(source, target)
    expected = read(out / 'provenance/expected-version.json')
    runtime_identity(out / 'identity-end', expected)
    final = checkpoint(out / 'final', config)
    assert_same_wake(read(out / 'attached/state.json'), final)
    # Seal files, not copies of source checkouts. The analyzer independently
    # reruns the native 96 MiB checks and reads both sides of every TCP block.
    files = {p.relative_to(out).as_posix(): {'bytes': p.stat().st_size, 'sha256': sha(p)}
             for p in sorted(out.rglob('*')) if p.is_file() and p.name != 'manifest.json'}
    write(out / 'manifest.json', dict(scope=SCOPE, files=files))
    analyzer = runpy.run_path(str(HERE.with_name('analyze.py')),
                             init_globals={'ROUND_ENTRY': ENTRY})
    result = analyzer['analyze'](out)
    write(out / 'analysis.json', result)
    print(json.dumps(result, indent=2))
    return 0 if result['ok'] else 1


def main(action):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True)
    if action == 'prepare':
        for name in ('config', 'pm-before', 'pm-after', 'accepted-capture'):
            parser.add_argument('--' + name, required=True)
    elif action == 'sustain':
        parser.add_argument('--seconds', type=int, default=300)
    else:
        parser.add_argument('--peer-a-log', required=True)
        parser.add_argument('--peer-b-log', required=True)
    args = parser.parse_args()
    try:
        result = {'prepare': prepare, 'sustain': sustain, 'finish': finish}[action](args)
        return result or 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(LABEL + ' failed:', exc)
        return 1
