#!/usr/bin/env python3
"""Four mainline checks: identity, domains, bytes, and one independent lifecycle."""
import argparse
import ipaddress
import json
import re
import struct
from common import (BASE_COMMIT, OFF_PHASES, PHASES, VERSIONS, module, project_path,
                    protocol as P, read_snapshot, roles, sha, write_json)

TREE = module('_r52_page_table_walker', 'tools/ordinary/analyze.py')
R50 = module('_r52_range_decoder', 'tools/pagetable/analyze.py')
need = TREE.need


def json_file(path):
    return json.loads(path.read_text(encoding='utf-8'))


def json_lines(path):
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]


def numeric_address(value):
    return str(ipaddress.IPv6Address(value.split('%', 1)[0]))


def analyze(cap):
    checks, states, controllers, data = [], {}, {}, {}

    def check(name, action):
        try:
            checks.append({'id': name, 'state': 'ok', 'detail': action()})
        except (OSError, ValueError, KeyError, IndexError, TypeError, struct.error, RuntimeError) as exc:
            checks.append({'id': name, 'state': 'FAIL', 'detail': str(exc)})

    def evidence():
        manifest, run = json_file(cap / 'manifest.json'), json_file(cap / 'run.json')
        mode = run['mode']
        need(mode in ('auto', 'off') and manifest['scope'] == 'r52' and
             manifest['mode'] == mode and not manifest['errors'], 'capture is incomplete')
        for name, expected in manifest['files'].items():
            raw = (cap / name).read_bytes()
            need(expected == {'bytes': len(raw), 'sha256': sha(raw)}, 'capture hash differs: ' + name)
        data.update(mode=mode, run=run, roles=roles(run['config']),
                    token=int((cap / 'token.txt').read_text(), 0))
        need(run['roles'] == data['roles'] and run['token'] == data['token'], 'run endpoint/token identity differs')
        for name in ('running-boot-args.txt', 'boot-args.txt'):
            boot = (cap / name).read_text().split()
            need([arg for arg in boot if arg.startswith('amdiommu=')] == ['amdiommu=' + mode],
                 'recorded boot mode differs')
        loaded = (cap / 'r52-version-confirmation.txt').read_text().lower()
        if mode == 'auto':
            source, expected = json_file(cap / 'source-ref.json'), json_file(cap / 'expected-version.json')
            need(source['base_commit'] == BASE_COMMIT and source['commit'] != BASE_COMMIT and
                 re.fullmatch(r'[0-9a-f]{40}', source['commit']), 'not a recorded R52 successor')
            for name, version in VERSIONS.items():
                got = manifest['installed'][name]
                need(got['version'] == version and got['codesign_returncode'] == 0 and
                     all(got[key] == expected[name][key] for key in ('version', 'sha256', 'uuid')) and
                     got['uuid'].lower() in loaded, 'installed/loaded identity differs: ' + name)
            need(all(manifest['installed']['RTL812xLucy'][name] is True for name in ('enableTSO4', 'enableTSO6')),
                 'R52 Lucy offloads differ')
        else:
            got = manifest['installed']['RTL812xLucy']
            need(got['codesign_returncode'] == 0 and got['uuid'].lower() in loaded,
                 'baseline Lucy installed/loaded identity missing')
        for phase in PHASES if mode == 'auto' else OFF_PHASES:
            phase_dir = cap / 'snapshots' / phase
            controllers[phase] = json_file(phase_dir / 'phase.json')['controller']
            states[phase] = {role: (read_snapshot(phase_dir / role) if mode == 'auto' else
                                   json_file(phase_dir / role / 'snapshot.json')) for role in ('a', 'b')}
        return {'mode': mode, 'versions': {name: row.get('version') for name, row in manifest['installed'].items()},
                'sourceCommit': source['commit'] if mode == 'auto' else None,
                'phases': list(states)}

    def domains():
        details, stable = {}, {}
        for phase, devices in states.items():
            for role, value in devices.items():
                binding, endpoint = value['binding'], data['roles'][role]
                need(all(binding[key] == endpoint[key] for key in
                         ('name', 'interface', 'bdf', 'requester')) and
                     binding['observed_requester'] == endpoint['requester'] and
                     binding['driver_registry_id'] > 0 and binding['pci_registry_id'] > 0,
                     phase + ': interface/PCI identity differs')
            need(len({v['binding']['driver_registry_id'] for v in devices.values()}) == 2,
                 'both endpoints selected the same Lucy instance')
            if data['mode'] == 'off':
                need(all(v['driver'].get('rtl812x-r44-mapped-dma', 0) == 0 for v in devices.values()),
                     'off baseline contains mapped DMA')
                details[phase] = {role: value['binding'] for role, value in devices.items()}
                continue
            controller = controllers[phase]
            need(controller['r52-domain-count'] == 2, 'shared controller must own the two selected domains')
            trees, identities, leaves = {}, [], {}
            for role, value in devices.items():
                p, d, m = value['probe'], value['driver'], value['mapper']
                ident = (p['r52-mapper-id'], p['r44-domain-id'], m['rootPA'])
                need(all(v > 0 for v in ident) and
                     p['r52-requester'] == p['r44-target-devid'] == value['binding']['requester'] and
                     d['rtl812x-r52-requester'] == p['r52-requester'] and
                     d['rtl812x-r52-mapper-id'] == ident[0] and d['rtl812x-r52-domain-id'] == ident[1] and
                     p['r52-owner-id'] == controller['registry_id'] and
                     p['r44-root-pa'] == m['rootPA'], phase + ': wrong mapper/domain binding')
                need(p['r44-device-table-pa'] == controller['r52-controller-device-table-pa'] and
                     p['r44-command-pa'] == controller['r52-controller-command-pa'],
                     'device mapper does not share the owner controller')
                need(p['r44-dte0'] & TREE.ADDRESS_MASK == m['rootPA'] and
                     p['r44-dte0'] & 3 == 3 and (p['r44-dte0'] >> 9) & 7 == 4 and
                     p['r44-dte1'] & 65535 == ident[1], 'DTE does not point at this domain root')
                identity = ident + (controller['registry_id'], p['r44-device-table-pa'], p['r44-command-pa'],
                                    value['binding']['driver_registry_id'])
                stable.setdefault(role, identity)
                need(stable[role] == identity, 'mapper/domain/controller changed across ordinary down/up')
                identities.append(ident)
                trees[role] = TREE.mapping_tree(value, iova_base=0x80000000, max_map_pages=64, max_runs=64)
                leaves[role] = TREE.leaves(value)[0]
            need(all(identities[0][i] != identities[1][i] for i in range(3)),
                 'the devices share a mapper, domain ID, or page-table root')
            overlap = sorted(set(leaves['a']) & set(leaves['b']))
            examples = [{'iova': address, 'a_pa': leaves['a'][address] & TREE.ADDRESS_MASK,
                         'b_pa': leaves['b'][address] & TREE.ADDRESS_MASK}
                        for address in overlap[:4]]
            details[phase] = {'devices': trees, 'identities': identities,
                              'overlappingIOVAPages': len(overlap), 'independentWalkExamples': examples}
        return details

    def traffic():
        mode, token = data['mode'], data['token']
        client = json_lines(cap / 'client.log')
        rows = [row for row in client if row.get('event') == 'transfer']
        need([(row['phase'], row['direction'], row['bytes']) for row in rows] == list(P.transfers(mode)),
             'finite client transfer set/order differs')
        need([row for row in client if row.get('event') == 'result'] ==
             [{'event': 'result', 'side': 'client', 'ok': True, 'family': 'IPv6', 'transfers': len(rows)}],
             'client did not finish successfully')
        peers = {}
        for role in ('a', 'b'):
            log = json_lines(cap / ('peer-' + role + '.log'))
            peer_rows = [row for row in log if row.get('event') == 'transfer']
            need([(row['phase'], row['direction'], row['bytes']) for row in peer_rows] ==
                 list(P.transfers(mode, role)), 'peer transfer set/order differs: ' + role)
            result = [row for row in log if row.get('event') == 'result']
            need(len(result) == 1 and result[0].get('ok') is True and
                 result[0].get('transfers') == len(peer_rows), 'peer did not finish: ' + role)
            peers.update({(row['phase'], row['direction']): row for row in peer_rows})
        for row in rows:
            phase, direction, size = row['phase'], row['direction'], row['bytes']
            peer, endpoint = peers[(phase, direction)], data['roles'][phase[0]]
            digest = P.expected_digest(token, phase, direction, size)
            for item in (row, peer):
                P.validate_receipt(item, token, phase, direction, size, digest)
            P.validate_transport(peer, row)
            need(row['peer_sha256'] == digest and row['peer_bytes'] == size and
                 row['peer_receipt_local'] == peer['local'] and row['peer_receipt_peer'] == peer['peer'],
                 'saved peer receipt differs from peer log')
            need(row['family'] == 'IPv6' and row['interface'] == endpoint['interface'] and
                 row['requester'] == endpoint['requester'] and
                 row['ifindex'] == row['bound_ifindex'] > 0 and
                 row['local']['address'] == numeric_address(endpoint['local_ipv6']) and
                 row['peer']['address'] == numeric_address(endpoint['peer_ipv6']) and
                 row['peer']['port'] == endpoint['port'], 'traffic is not bound to its selected endpoint')
        initial = {role: [row for row in rows if row['phase'] == role + '-before'] for role in ('a', 'b')}
        need(any(max(a['payload_start_ns'], b['payload_start_ns']) <
                 min(a['payload_end_ns'], b['payload_end_ns'])
                 for a in initial['a'] for b in initial['b']),
             'initial payload intervals did not overlap across the two interfaces')
        data.update(client=client, transfers=rows)
        return {'transfers': len(rows), 'bytes': sum(row['bytes'] for row in rows),
                'dualEndHash': True, 'interfaceBoundIPv6': True, 'concurrentPayloads': True}

    def lifecycle():
        if data['mode'] == 'off':
            return {'baseline': 'both explicit endpoints completed short physical-DMA IPv6 TCP',
                    'mapperRequired': False}
        before, down, after = (states[name] for name in PHASES)
        for role in ('a', 'b'):
            b, d, a = [values[role]['driver'] for values in (before, down, after)]
            if role == 'a':
                need(d['rtl812x-r44-state'] == 'disabled' and a['rtl812x-r44-state'] == 'enabled' and
                     d['rtl812x-r44-disable-count'] == b['rtl812x-r44-disable-count'] + 1 and
                     a['rtl812x-r44-enable-count'] == b['rtl812x-r44-enable-count'] + 1,
                     'selected down target did not complete one ordinary down/up')
            else:
                need(all(v['rtl812x-r44-state'] == 'enabled' for v in (b, d, a)) and
                     len({v['rtl812x-r44-disable-count'] for v in (b, d, a)}) == 1 and
                     len({v['rtl812x-r44-enable-count'] for v in (b, d, a)}) == 1,
                     'the other interface was reset/disabled during the selected lifecycle')
            prefix = 'rtl812x-r46-tso6-'
            need(a[prefix + 'posted'] > b[prefix + 'posted'] and
                 all(v[prefix + 'posted'] == v[prefix + 'completed'] for v in (b, d, a)),
                 role + ': real IPv6 TSO work did not complete')
        events = {name: [row for row in data['client'] if row.get('event') == name]
                  for name in ('ifdown-done', 'ifup-requested')}
        need(all(len(value) == 1 for value in events.values()), 'ordinary lifecycle timestamps missing')
        begin, end = (events[name][0]['time_ns'] for name in ('ifdown-done', 'ifup-requested'))
        held = [row for row in data['transfers'] if row['phase'] == 'b-during-down']
        need(len(held) == 2 and all(begin < row['start_ns'] < row['end_ns'] < end for row in held),
             'other-domain byte-verified transfers did not finish while the target was down')
        need(down['b']['mapper']['mapOk'] > before['b']['mapper']['mapOk'] and
             down['b']['mapper']['unmapOk'] > before['b']['mapper']['unmapOk'] and
             after['a']['mapper']['mapOk'] > down['a']['mapper']['mapOk'],
             'real traffic did not exercise both domain map/unmap paths')
        details = {}
        for phase, devices in states.items():
            controller = controllers[phase]
            completed = controller['r52-controller-cmd-completed']
            need(completed == controller['r52-controller-cmd-completion-sequence'] ==
                 controller['r52-controller-cmd-submits'] and
                 controller['r52-controller-ready'] == controller['r52-controller-event-valid'] == 'yes' and
                 controller['r52-controller-command-failed'] == controller['r52-controller-event-overflow'] == 'no' and
                 controller['r52-controller-target-faults'] == 0, 'shared command/event path failed')
            counters = {}
            for role, value in devices.items():
                p, m = value['probe'], value['mapper']
                skipped = p['r51-map-invalidation-skipped']
                expected_skip = 0 if p['r51-npcache'] else m['mapOk'] - 1
                expected_inv = m['mapOk'] + m['unmapOk'] - skipped
                need(p['r44-controller-ready'] == p['r44-dte-active'] == 'yes' and
                     p['r44-event-valid'] == 'yes' and
                     p['r51-npcache'] == ((p['r47-cap-header'] >> 26) & 1) and
                     m['flags'] == 3 and m['liveCount'] == 19 and
                     m['mapCalls'] == m['mapOk'] and m['unmapCalls'] == m['unmapOk'] and
                     m['mapOk'] - m['unmapOk'] == 19 and
                     m['mapRejected'] == m['unmapRejected'] == m['invalidateFailures'] == 0 and
                     skipped == expected_skip and m['invalidates'] == p['r44-inv-pages-completed'] == expected_inv and
                     p['r52-domain-cmd-completed'] == expected_inv + 1 and
                     p['r50-inv-full-completed'] == 1 and p['r50-inv-range-completed'] == expected_inv - 1 and
                     p['r50-last-range-sequence'] <= p['r44-cmd-completed'] <= completed and
                     p['r44-target-faults'] == 0 and
                     p['r44-command-failed'] == 'no' and p['r44-event-overflow'] == 'no',
                     phase + '/' + role + ': map/unmap or invalidation/fault accounting differs')
                if m['unmapOk']:
                    row = m['lastUnmap']
                    need(row['state'] == 15 and row['tClear'] <= row['tUnmapComplete'] <= m['snapshotTime'],
                         'unmap did not complete before retirement')
                if p['r50-inv-range-completed']:
                    words = [p['r50-last-range-command%d' % index] for index in range(4)]
                    start, size = R50.decode_range(words, p['r44-domain-id'])
                    address, requested = p['r50-last-range-address'], p['r50-last-range-bytes']
                    need(m['iovaBase'] <= start <= address and
                         address + requested <= start + size <= m['iovaBase'] + m['iovaBytes'] and
                         requested > 0 and requested % 4096 == 0,
                         'last completed range does not cover this domain IOVA mapping')
                counters[role] = {'mapOk': m['mapOk'], 'unmapOk': m['unmapOk'],
                                  'mapSkipped': skipped, 'domainCommands': p['r52-domain-cmd-completed']}
            details[phase] = {'controllerCommands': completed, 'devices': counters}
        return {'otherDeviceTrafficWhileTargetDown': True, 'sameConnectionAcrossTransition': 'not tested',
                'targetFaults': 0, 'counters': details}

    check('capture-and-runtime-identity', evidence)
    expected_phases = PHASES if data.get('mode') == 'auto' else OFF_PHASES
    if len(states) == len(expected_phases):
        check('two-endpoints-and-independent-domain-trees', domains)
        check('interface-bound-ipv6-and-dual-end-hashes', traffic)
        if 'client' in data:
            check('one-device-down-other-device-business-and-retirement', lifecycle)
    return {'scope': 'r52-two-device-shared-controller', 'mode': data.get('mode'),
            'ok': len(checks) == 4 and all(row['state'] == 'ok' for row in checks), 'checks': checks,
            'limitations': ['One selected interface down/up; the other completes traffic while it is down.',
                            'No claim of one continuous connection across the transitions, system-wide IOMapper, PM or hot-unplug.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture')
    parser.add_argument('--json', dest='output')
    args = parser.parse_args()
    result = analyze(project_path(args.capture))
    if args.output:
        write_json(project_path(args.output), result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
