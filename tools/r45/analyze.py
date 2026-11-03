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


def analyze(cap, *, round_id=45, base_commit=BASE_COMMIT, versions=None,
            protocol=None, tso_version=4, tcp_record_check=None,
            iova_base=0x1000000000, max_map_pages=32, max_runs=32,
            rx_groups=64, rx_group_pages=16):
    # R46 reuses the accepted mapper/lifecycle checks and supplies only its
    # IPv6 transport, TSO counters and source/binary identity differences.
    versions = VERSIONS if versions is None else versions
    protocol = P if protocol is None else protocol
    round_name = 'r%d' % round_id
    tso_prefix = PREFIX if tso_version == 4 else 'rtl812x-r46-'
    tso_name = 'tso%d' % tso_version
    checks, states = [], {}

    def check(name, function):
        try:
            detail = function()
            checks.append({'id': name, 'state': 'ok', 'detail': detail})
        except (OSError, ValueError, KeyError, IndexError, TypeError, struct.error) as exc:
            checks.append({'id': name, 'state': 'FAIL', 'detail': str(exc)})

    def result():
        return {'scope': '%s-ordinary-ipv%d-tcp-tso' % (round_name, tso_version),
                'ok': len(checks) == 9 and all(c['state'] == 'ok' for c in checks),
                'checks': checks, 'limitations': [
                    'One target NIC, MTU1500, IPv%d TSO and one ordinary interface down/up.' % tso_version,
                    'Throughput is observed without a line-rate threshold; normal TCP retransmission is allowed.',
                    'The domain remains active with %d RX groups and 3 fixed mappings while the interface is down.' % rx_groups,
                    ('This run does not establish IPv6 TSO, system-wide IOMapper, full PM or multi-device support.'
                     if tso_version == 4 else
                     'This run does not establish system-wide IOMapper, full PM or multi-device support.')]}

    def capture_identity():
        manifest = json.loads((cap / 'manifest.json').read_text())
        need(manifest['scope'] == round_name and not manifest['errors'], 'capture reports missing evidence')
        for name, wanted in manifest['files'].items():
            data = (cap / name).read_bytes()
            need(wanted == {'bytes': len(data), 'sha256': sha(data)}, 'capture hash differs: ' + name)
        source = json.loads((cap / 'source-ref.json').read_text())
        need(source['base_commit'] == base_commit and
             re.fullmatch('[0-9a-f]{40}', source['commit']) and source['commit'] != base_commit,
             'source is not a recorded R%d successor' % round_id)
        expected = json.loads((cap / 'expected-version.json').read_text())
        loaded = (cap / (round_name + '-version-confirmation.txt')).read_text().lower()
        for name, version in versions.items():
            got = manifest['installed'][name]
            need(got['version'] == version and got['codesign_returncode'] == 0 and
                 all(got[key] == expected[name][key] for key in ('version', 'sha256', 'uuid')) and
                 got['uuid'].lower() in loaded and re.fullmatch('[0-9a-f]{64}', got['sha256']),
                 'installed/loaded binary identity differs: ' + name)
        driver = manifest['installed']['RTL812xLucy']
        need(driver['enableTSO4'] is True and driver['enableTSO6'] is (tso_version == 6),
             'IPv4 TSO must be enabled and IPv6 TSO must remain off' if tso_version == 4 else
             'IPv4 and IPv6 TSO must both be enabled')
        boot = (cap / 'boot-args.txt').read_text().split()
        need([v for v in boot if v.startswith('amdiommu=')] == ['amdiommu=auto'],
             'this boot did not select ordinary auto mode')
        need(re.search(r'\bmtu 1500\b', (cap / 'network.txt').read_text()), 'target MTU is not 1500')
        for label in PHASES:
            states[label] = read_snapshot(cap / 'snapshots' / label)
        return {'sourceCommit': source['commit'], 'versions': versions, 'snapshots': len(states),
                'mtu': 1500, 'tsoIPv4': True, 'tsoIPv6': tso_version == 6}
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
             (rx_groups, 1024, 3), 'normal Lucy resource shape differs')
        return {'reset': reset, 'firstPrepare': prepare, 'dteActive': p['r44-dte-active-time'],
                'firstMapComplete': m['firstMapAt'], 'resourcesReady': ready, 'dmaEnabled': enabled}
    check('automatic-device-mapper-and-startup-order', startup)

    check('complete-live-records-match-whole-iova-tree',
          lambda: {label: R44.mapping_tree(states[label], iova_base=iova_base,
                       max_map_pages=max_map_pages, max_runs=max_runs) for label in PHASES})

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
        expected = {(phase, direction): size for phase, direction, size in protocol.TRANSFERS}
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
        for phase, direction, size in protocol.TRANSFERS:
            key = (phase, direction)
            digest = protocol.expected_digest(token, phase, direction, size)
            client, peer = (records[side][key] for side in ('client', 'peer'))
            for side, row in (('client', client), ('peer', peer)):
                need(row['sha256'] == row['expected_sha256'] == digest,
                     '%s %s %s: TCP SHA256 differs' % (side, phase, direction))
            need(client['peer_bytes'] == size and client['peer_sha256'] == peer['sha256'],
                 phase + ' ' + direction + ': peer acknowledgement differs')
            transfer = {'phase': phase, 'direction': direction, 'bytes': size, 'sha256': digest,
                        'clientMiBPerSecond': size * 1e9 / (1048576 * client['duration_ns']),
                        'peerMiBPerSecond': size * 1e9 / (1048576 * peer['duration_ns'])}
            if tcp_record_check is not None:
                transfer['transport'] = tcp_record_check(client, peer)
            detail.append(transfer)
        return {'transfers': detail, 'totalBytes': sum(expected.values()),
                'throughputThreshold': None, 'normalTCPRetransmissionAllowed': True}
    check('four-tcp-transfers-and-end-to-end-byte-integrity', traffic)

    def tso():
        detail = {'snapshots': {}, 'intervals': {}}
        for label, value in states.items():
            d = value['driver']
            need(d[PREFIX + 'tso4-enabled'] == 1 and
                 d[PREFIX + 'tso6-enabled'] == int(tso_version == 6),
                 label + ': running TSO configuration differs')
            families = [(PREFIX, 'tso4')]
            if tso_version == 6:
                families.append((tso_prefix, tso_name))
            for prefix, family in families:
                need(d[prefix + family + '-posted'] == d[prefix + family + '-completed'] and
                     d[prefix + family + '-posted-bytes'] == d[prefix + family + '-completed-bytes'] and
                     d[prefix + family + '-stop-retired'] == 0,
                     label + ': posted TSO packets were not completed by hardware before capture')
            detail['snapshots'][label] = {
                key: d[tso_prefix + key] for key in ['snapshot-seq'] + [
                    tso_name + '-' + key for key in (
                        'posted', 'completed', 'stop-retired', 'posted-bytes', 'completed-bytes',
                        'max-length', 'max-segments', 'max-mss')]}
            detail['snapshots'][label].update({key: d[PREFIX + key]
                for key in ('tx-free-commands', 'tx-free-descriptors')})
            if tso_version == 6:
                detail['snapshots'][label]['ipv4'] = {key: d[PREFIX + key] for key in (
                    'snapshot-seq', 'tso4-posted', 'tso4-completed', 'tso4-stop-retired',
                    'tso4-posted-bytes', 'tso4-completed-bytes')}
        for begin, end in (('before', 'pre-down'), ('down', 'after-up')):
            first, last = states[begin]['driver'], states[end]['driver']
            delta = {tso_name + '-' + key:
                     last[tso_prefix + tso_name + '-' + key] - first[tso_prefix + tso_name + '-' + key]
                     for key in ('posted', 'completed', 'posted-bytes', 'completed-bytes')}
            need(all(value > 0 for value in delta.values()) and
                 delta[tso_name + '-posted'] == delta[tso_name + '-completed'] and
                 delta[tso_name + '-posted-bytes'] == delta[tso_name + '-completed-bytes'],
                 begin + ' -> ' + end + ': no completed TSO%d work from this TCP phase' % tso_version)
            need(last[tso_prefix + tso_name + '-max-length'] > 1514 and
                 last[tso_prefix + tso_name + '-max-segments'] > 1 and
                 last[tso_prefix + tso_name + '-max-mss'] > 0,
                 end + ': actual large multisegment TSO%d descriptor evidence is missing' % tso_version)
            detail['intervals'][begin + ' -> ' + end] = delta
        return detail
    check('actual-tso%d-posted-and-hardware-completed-in-both-phases' % tso_version, tso)

    def persistent():
        values = [list(identity(states[label])) for label in PHASES]
        need(all(v == values[0] and all(x > 0 for x in v) for v in values),
             'device domain was recreated across TCP or interface down/up')
        sequences = ([states[label]['mapper']['snapshotTime'] for label in PHASES],
                     [states[label]['mapper']['snapshotSequence'] for label in PHASES],
                     [states[label]['driver'][tso_prefix + 'snapshot-seq'] for label in PHASES])
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
        retained_maps = rx_groups + 3
        need(down['mapper']['liveCount'] == retained_maps,
             'interface down must retain %d resource mappings' % retained_maps)
        fixed_handles, rx_handles = {}, {}
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
            if label == 'down' or rx_group_pages > 32:
                rx = [row for row in rows if row['handle'] not in fixed]
                need(len(rx) == rx_groups and all(row['length'] == rx_group_pages * 4096 and
                     row['pages'] == rx_group_pages for row in rx),
                     label + ': does not retain exactly %d ordinary RX groups of %d pages' %
                     (rx_groups, rx_group_pages))
                rx_handles[label] = {row['handle'] for row in rx}
            if rx_group_pages > 32:
                # R49's real RX commands exceed the old 128 KiB limit. The
                # complete live records/PT already prove every backing page.
                need((d['rtl812x-r44-rx-groups'], d['rtl812x-r44-rx-slots'],
                      d['rtl812x-r44-fixed-mappings']) == (rx_groups, 1024, 3) and
                     rx_groups * rx_group_pages == 1024 and
                     value['mapper']['liveCount'] == retained_maps and
                     value['mapper']['livePages'] == 1024 + 13 and
                     value['mapper']['maxObservedPages'] >= rx_group_pages,
                     label + ': actual large RX mapping geometry differs')
        need(all(v == fixed_handles['before'] for v in fixed_handles.values()),
             'persistent fixed resources were recreated')
        detail = {'downLiveMaps': retained_maps, 'rxGroups': rx_groups, 'fixedMappings': 3,
                  'enableCount': ad['rtl812x-r44-enable-count'], 'disableCount': dd['rtl812x-r44-disable-count']}
        if rx_group_pages > 32:
            for begin, end in (('before', 'pre-down'), ('down', 'after-up')):
                need(rx_handles[begin] != rx_handles[end],
                     begin + ' -> ' + end + ': large RX commands were not remapped during traffic')
            detail.update(rxGroupPages=rx_group_pages, rxGroupBytes=rx_group_pages * 4096,
                          largeRxRemappedInBothPhases=True, livePages=1037)
        return detail
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
