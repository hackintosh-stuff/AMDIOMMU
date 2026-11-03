#!/usr/bin/env python3
"""Accept ordinary IPv4 TCP/TSO through the existing per-device IOMapper."""
import argparse
import json
import re
import struct
from common import (PHASES, VERSIONS, active, identity, module, protocol as P,
                    project_path, read_snapshot, sha, write_json)

BASE_COMMIT = '035d1dd0f5e60afbc5f2715de3f425cb694d3f56'
ADDRESS_MASK = 0x000FFFFFFFFFF000
R44 = module('_r45_r44_analyzer', 'tools/r44/analyze.py')
PREFIX = 'rtl812x-r45-'


def need(condition, message):
    if not condition:
        raise ValueError(message)


def log_rows(path):
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    need(all(isinstance(row, dict) for row in rows), 'JSONL records must be objects: ' + path.name)
    return rows


def analyze(cap):
    checks, states = [], {}

    def check(name, function):
        try:
            detail = function()
            checks.append({'id': name, 'state': 'ok', 'detail': detail})
        except (OSError, ValueError, KeyError, IndexError, TypeError, struct.error) as exc:
            checks.append({'id': name, 'state': 'FAIL', 'detail': str(exc)})

    def result():
        return {'scope': 'r45-ordinary-ipv4-tcp-tso',
                'ok': len(checks) == 9 and all(c['state'] == 'ok' for c in checks),
                'checks': checks, 'limitations': [
                    'One target NIC, MTU1500, IPv4 TSO and one ordinary interface down/up.',
                    'Throughput is observed without a line-rate threshold; normal TCP retransmission is allowed.',
                    'The domain remains active with 64 RX groups and 3 fixed mappings while the interface is down.',
                    'This run does not establish IPv6 TSO, system-wide IOMapper, full PM or multi-device support.']}

    def capture_identity():
        manifest = json.loads((cap / 'manifest.json').read_text())
        need(manifest['scope'] == 'r45' and not manifest['errors'], 'capture reports missing evidence')
        for name, wanted in manifest['files'].items():
            data = (cap / name).read_bytes()
            need(wanted == {'bytes': len(data), 'sha256': sha(data)}, 'capture hash differs: ' + name)
        source = json.loads((cap / 'source-ref.json').read_text())
        need(source['base_commit'] == BASE_COMMIT and
             re.fullmatch('[0-9a-f]{40}', source['commit']) and source['commit'] != BASE_COMMIT,
             'source is not a recorded R45 successor')
        expected = json.loads((cap / 'expected-version.json').read_text())
        loaded = (cap / 'r45-version-confirmation.txt').read_text().lower()
        for name, version in VERSIONS.items():
            got = manifest['installed'][name]
            need(got['version'] == version and got['codesign_returncode'] == 0 and
                 all(got[key] == expected[name][key] for key in ('version', 'sha256', 'uuid')) and
                 got['uuid'].lower() in loaded and re.fullmatch('[0-9a-f]{64}', got['sha256']),
                 'installed/loaded binary identity differs: ' + name)
        driver = manifest['installed']['RTL812xLucy']
        need(driver['enableTSO4'] is True and driver['enableTSO6'] is False,
             'IPv4 TSO must be enabled and IPv6 TSO must remain off')
        boot = (cap / 'boot-args.txt').read_text().split()
        need([v for v in boot if v.startswith('amdiommu=')] == ['amdiommu=auto'],
             'this boot did not select ordinary auto mode')
        need(re.search(r'\bmtu 1500\b', (cap / 'network.txt').read_text()), 'target MTU is not 1500')
        for label in PHASES:
            states[label] = read_snapshot(cap / 'snapshots' / label)
        return {'sourceCommit': source['commit'], 'versions': VERSIONS, 'snapshots': len(states),
                'mtu': 1500, 'tsoIPv4': True, 'tsoIPv6': False}
    check('capture-source-binary-and-tso-configuration', capture_identity)
    if len(states) != len(PHASES):
        return result()

    def startup():
        first = states['before']
        p, d, m = first['probe'], first['driver'], first['mapper']
        need(all(active(v) for v in states.values()), 'ordinary mapper is not active in every phase')
        need(p['r44-parent'] == 'set-before-driver-start' and p['r44-system-mapper'] == 'no' and
             d['rtl812x-r44-mode'] == 'auto', 'per-device automatic discovery differs')
        reset = d['rtl812x-r44-reset-done-time']
        prepare = d['rtl812x-r44-first-dma-prepare-time']
        ready = d['rtl812x-r44-resources-ready-time']
        enabled = d['rtl812x-r44-enable-time']
        need(0 < p['r44-controller-ready-time'] <= reset < prepare <=
             p['r44-dte-active-time'] <= m['firstMapAt'] < ready < enabled < m['snapshotTime'],
             'ordinary reset/first-map/DTE/resources/DMA-enable order differs')
        need(d['rtl812x-r44-reset-command'] & 12 == 0 and
             d['rtl812x-r44-enable-command'] & 12 == 12, 'DMA command readback differs')
        need((d['rtl812x-r44-rx-groups'], d['rtl812x-r44-rx-slots'], d['rtl812x-r44-fixed-mappings']) ==
             (64, 1024, 3), 'normal Lucy resource shape differs')
        return {'reset': reset, 'firstPrepare': prepare, 'dteActive': p['r44-dte-active-time'],
                'firstMapComplete': m['firstMapAt'], 'resourcesReady': ready, 'dmaEnabled': enabled}
    check('automatic-device-mapper-and-startup-order', startup)

    check('complete-live-records-match-whole-iova-tree',
          lambda: {label: R44.mapping_tree(states[label]) for label in PHASES})

    def lifecycle():
        detail = {}
        for label, value in states.items():
            m, p = value['mapper'], value['probe']
            need(m['mapCalls'] == m['mapOk'] and m['unmapCalls'] == m['unmapOk'] and
                 m['mapOk'] - m['unmapOk'] == m['liveCount'] and
                 m['mapRejected'] == m['unmapRejected'] == m['invalidateFailures'] == 0,
                 label + ': map/unmap accounting differs')
            need(m['invalidates'] == m['mapOk'] + m['unmapOk'] == p['r44-inv-pages-completed'],
                 label + ': INV/CW accounting differs')
            row = m['lastUnmap']
            if m['unmapOk']:
                need(row['state'] == 15 and 0 < row['tPublish'] <= row['tMapComplete'] <
                     row['tClear'] <= row['tUnmapComplete'] <= m['snapshotTime'],
                     label + ': last unmap was not completed before page reuse')
            need(value['driver'][PREFIX + 'map-failures'] == 0,
                 label + ': ordinary TX mapping failed')
            detail[label] = {key: m[key] for key in ('mapOk', 'unmapOk', 'liveCount', 'livePages',
                                                    'peakMaps', 'peakPages', 'maxObservedPages',
                                                    'maxObservedRuns', 'offsetMaps', 'fragmentedMaps')}
            detail[label]['commandWaits'] = value['driver'][PREFIX + 'command-waits']
        for begin, end in (('before', 'pre-down'), ('down', 'after-up')):
            first, last = states[begin]['mapper'], states[end]['mapper']
            need(last['mapOk'] > first['mapOk'] and last['unmapOk'] > first['unmapOk'] and
                 last['reusedAllocations'] > first['reusedAllocations'],
                 begin + ' -> ' + end + ': packet mapping/retirement/reuse was not exercised')
        return detail
    check('ordinary-mapping-retirement-and-reuse', lifecycle)

    def traffic():
        token = int((cap / 'token.txt').read_text().strip(), 0)
        logs = {side: log_rows(cap / (side + '.log')) for side in ('client', 'peer')}
        expected = {(phase, direction): size for phase, direction, size in P.TRANSFERS}
        records = {}
        for side, rows in logs.items():
            transfers = [row for row in rows if row.get('event') == 'transfer']
            need(len(transfers) == len(expected), side + ': four complete TCP transfers required')
            indexed = {}
            for row in transfers:
                key = (row['phase'], row['direction'])
                need(row['side'] == side and key in expected and key not in indexed,
                     side + ': unknown/duplicate TCP transfer')
                need(row['token'] == token and row['bytes'] == expected[key] and row['verified'] is True,
                     side + ': TCP token/bytes/pattern verification differs')
                need(isinstance(row['duration_ns'], int) and row['duration_ns'] > 0,
                     side + ': positive transfer duration required')
                indexed[key] = row
            need(set(indexed) == set(expected), side + ': a TCP transfer is missing')
            need(not any(row.get('event') == 'error' for row in rows), side + ': TCP log reports an error')
            records[side] = indexed
        outcomes = [row for row in logs['client'] if row.get('event') == 'result']
        need(len(outcomes) == 1 and outcomes[0].get('ok') is True, 'client did not finish successfully')
        detail = []
        for phase, direction, size in P.TRANSFERS:
            key = (phase, direction)
            digest = P.expected_digest(token, phase, direction, size)
            client, peer = (records[side][key] for side in ('client', 'peer'))
            for side, row in (('client', client), ('peer', peer)):
                need(row['sha256'] == row['expected_sha256'] == digest,
                     '%s %s %s: TCP SHA256 differs' % (side, phase, direction))
            need(client['peer_bytes'] == size and client['peer_sha256'] == peer['sha256'],
                 phase + ' ' + direction + ': peer acknowledgement differs')
            detail.append({'phase': phase, 'direction': direction, 'bytes': size, 'sha256': digest,
                           'clientMiBPerSecond': size * 1e9 / (1048576 * client['duration_ns']),
                           'peerMiBPerSecond': size * 1e9 / (1048576 * peer['duration_ns'])})
        return {'transfers': detail, 'totalBytes': sum(expected.values()),
                'throughputThreshold': None, 'normalTCPRetransmissionAllowed': True}
    check('four-tcp-transfers-and-end-to-end-byte-integrity', traffic)

    def tso():
        detail = {'snapshots': {}, 'intervals': {}}
        for label, value in states.items():
            d = value['driver']
            need(d[PREFIX + 'tso4-enabled'] == 1 and d[PREFIX + 'tso6-enabled'] == 0,
                 label + ': running TSO configuration differs')
            need(d[PREFIX + 'tso4-posted'] == d[PREFIX + 'tso4-completed'] and
                 d[PREFIX + 'tso4-posted-bytes'] == d[PREFIX + 'tso4-completed-bytes'] and
                 d[PREFIX + 'tso4-stop-retired'] == 0,
                 label + ': posted TSO packets were not completed by hardware before capture')
            detail['snapshots'][label] = {
                key: d[PREFIX + key] for key in (
                    'snapshot-seq', 'tso4-posted', 'tso4-completed', 'tso4-stop-retired',
                    'tso4-posted-bytes', 'tso4-completed-bytes', 'tso4-max-length',
                    'tso4-max-segments', 'tso4-max-mss', 'tx-free-commands', 'tx-free-descriptors')}
        for begin, end in (('before', 'pre-down'), ('down', 'after-up')):
            first, last = states[begin]['driver'], states[end]['driver']
            delta = {key: last[PREFIX + key] - first[PREFIX + key] for key in (
                'tso4-posted', 'tso4-completed', 'tso4-posted-bytes', 'tso4-completed-bytes')}
            need(all(value > 0 for value in delta.values()) and
                 delta['tso4-posted'] == delta['tso4-completed'] and
                 delta['tso4-posted-bytes'] == delta['tso4-completed-bytes'],
                 begin + ' -> ' + end + ': no completed TSO4 work from this TCP phase')
            need(last[PREFIX + 'tso4-max-length'] > 1514 and last[PREFIX + 'tso4-max-segments'] > 1 and
                 last[PREFIX + 'tso4-max-mss'] > 0,
                 end + ': actual large multisegment TSO4 descriptor evidence is missing')
            detail['intervals'][begin + ' -> ' + end] = delta
        return detail
    check('actual-tso4-posted-and-hardware-completed-in-both-phases', tso)

    def persistent():
        values = [list(identity(states[label])) for label in PHASES]
        need(all(v == values[0] and all(x > 0 for x in v) for v in values),
             'device domain was recreated across TCP or interface down/up')
        sequences = ([states[label]['mapper']['snapshotTime'] for label in PHASES],
                     [states[label]['mapper']['snapshotSequence'] for label in PHASES],
                     [states[label]['driver'][PREFIX + 'snapshot-seq'] for label in PHASES])
        need(all(all(a < b for a, b in zip(values, values[1:])) for values in sequences),
             'mapper/driver snapshot order differs')
        return {'sameDomain': True, 'identity': values[0], 'phases': list(PHASES)}
    check('same-device-domain-through-all-four-stages', persistent)

    def normal_lifecycle():
        before, down, after = (states[name] for name in ('pre-down', 'down', 'after-up'))
        bd, dd, ad = (v['driver'] for v in (before, down, after))
        need(dd['rtl812x-r44-state'] == 'disabled' and ad['rtl812x-r44-state'] == 'enabled' and
             dd['rtl812x-r44-disable-count'] == bd['rtl812x-r44-disable-count'] + 1 and
             ad['rtl812x-r44-enable-count'] > bd['rtl812x-r44-enable-count'],
             'ordinary disable/enable events missing')
        need(before['mapper']['snapshotTime'] < dd['rtl812x-r44-disable-time'] <
             down['mapper']['snapshotTime'] < ad['rtl812x-r44-enable-time'] < after['mapper']['snapshotTime'] and
             dd['rtl812x-r44-disable-command'] & 12 == 0 and ad['rtl812x-r44-enable-command'] & 12 == 12,
             'ordinary DMA stop/re-enable order/readback differs')
        need(down['mapper']['liveCount'] == 67, 'interface down must retain 67 resource mappings')
        fixed_handles = {}
        for label, value in states.items():
            d, rows = value['driver'], value['live']
            fixed = []
            for kind, length in (('tx', 32768), ('rx', 16384), ('tally', 192)):
                address = d['rtl812x-r44-' + kind + '-iova']
                matches = [row for row in rows if row['mapAddress'] == address]
                need(len(matches) == 1 and matches[0]['length'] == length,
                     label + ': fixed DMA object missing from ordinary mappings')
                if label != 'down':
                    need(d['rtl812x-r44-' + kind + '-register'] == address,
                         label + ': hardware DMA base is not its mapped address')
                fixed.append(matches[0]['handle'])
            fixed_handles[label] = fixed
            if label == 'down':
                rx = [row for row in rows if row['handle'] not in fixed]
                need(len(rx) == 64 and all(row['length'] == 65536 and row['pages'] == 16 for row in rx),
                     'down does not retain exactly 64 ordinary RX groups')
        need(all(v == fixed_handles['before'] for v in fixed_handles.values()),
             'persistent fixed resources were recreated')
        return {'downLiveMaps': 67, 'rxGroups': 64, 'fixedMappings': 3,
                'enableCount': ad['rtl812x-r44-enable-count'], 'disableCount': dd['rtl812x-r44-disable-count']}
    check('ordinary-interface-down-up-with-retained-resources', normal_lifecycle)

    def hardware():
        for label, value in states.items():
            p, m = value['probe'], value['mapper']
            need(p['r44-target-faults'] == 0 and p['r44-event-overflow'] == 'no' and
                 p['r44-event-valid'] == 'yes' and p['r44-command-failed'] == 'no',
                 label + ': hardware fault/event failure')
            need(p['r44-inv-dev-completed'] == 1 and p['r44-cmd-submits'] == p['r44-cmd-completed'] ==
                 p['r44-inv-pages-completed'] + 1 and p['r44-cmd-completion-sequence'] == p['r44-cmd-completed'],
                 label + ': command completion differs')
            need(p['r44-dte0'] & ADDRESS_MASK == m['rootPA'] and (p['r44-dte0'] >> 9) & 7 == 4 and
                 p['r44-dte0'] & 3 == 3 and p['r44-dte1'] & 65535 == p['r44-domain-id'],
                 label + ': active device table entry differs')
        last = states['after-up']['probe']
        need(last['r44-cmd-wraps'] > 0 and last['r44-cmd-post-wrap'] > 0, 'command ring did not pass wrap')
        return {'commandsCompleted': last['r44-cmd-completed'], 'wraps': last['r44-cmd-wraps'],
                'targetFaults': 0}
    check('hardware-command-completion-and-no-target-faults', hardware)
    return result()


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
