#!/usr/bin/env python3
"""Accept the ordinary per-device mapper mainline from saved evidence."""
import argparse
import json
import re
import struct
from common import (PHASES, VERSIONS, active, identity, protocol as P,
                    project_path, read_snapshot, sha, write_json)

BASE_COMMIT = '102560a59bc448ddfd5600d5d958952e4875eb16'
ADDRESS_MASK = 0x000FFFFFFFFFF000


def need(condition, message):
    if not condition:
        raise ValueError(message)


def leaves(value):
    m, data = value['mapper'], value['pt']
    need(len(data) == m['ptBytes'] == m['tablePages'] * 4096, 'PT arena size differs')
    found, seen = {}, set()

    def walk(pa, level, base):
        need(pa % 4096 == 0 and m['rootPA'] <= pa <= m['rootPA'] + len(data) - 4096,
             'table pointer leaves the captured arena')
        need(pa not in seen, 'page table alias/cycle')
        seen.add(pa)
        for index, raw in enumerate(struct.unpack_from('<512Q', data, pa - m['rootPA'])):
            if not raw & 1:
                continue
            address = base + (index << (12 + 9 * (level - 1)))
            next_level, target = (raw >> 9) & 7, raw & ADDRESS_MASK
            if next_level:
                need(next_level == level - 1, 'unexpected next-level encoding')
                walk(target, next_level, address)
            else:
                need(level == 1, 'ordinary mapper must use 4 KiB leaves')
                found[address] = raw
    walk(m['rootPA'], m['rootLevel'], 0)
    return found, len(seen)


def mapping_tree(value):
    m, rows = value['mapper'], value['live']
    need((m['capacityMaps'], m['capacityPages'], m['maxMapPages'], m['maxRuns']) ==
         (1024, 4096, 32, 32), 'ordinary mapper capacity differs')
    need(m['rootLevel'] == 4 and m['iovaBase'] == 0x1000000000 and
         m['iovaBytes'] == 4096 * 4096, 'ordinary IOVA domain geometry differs')
    expected, handles, slots = {}, set(), set()
    for row in rows:
        need(row['handle'] and row['handle'] not in handles and
             row['recordIndex'] not in slots, 'duplicate live handle/record slot')
        handles.add(row['handle'])
        slots.add(row['recordIndex'])
        need(row['recordIndex'] < 1024 and 0 < row['pages'] <= 32 and
             0 < row['runs'] <= 32 and row['basePage'] + row['pages'] <= 4096,
             'live allocation exceeds normal pool')
        need(row['state'] == 3 and 0 < row['tPublish'] <= row['tMapComplete'] <= m['snapshotTime'] and
             row['tClear'] == row['tUnmapComplete'] == 0, 'live record lifecycle is not confirmed')
        first_offset = row['firstPA'] & 4095
        base = m['iovaBase'] + row['basePage'] * 4096
        need(row['mapAddress'] == base + first_offset and
             0 < row['length'] <= row['mapLength'] <= row['pages'] * 4096 - first_offset,
             'mapping byte span differs')
        need(row['physical'][0] == (row['firstPA'] & ~4095) and
             not any(row['physical'][row['pages']:]), 'physical-page evidence differs')
        permissions = ((1 << 61) if row['options'] & 1 else 0) | ((1 << 62) if row['options'] & 2 else 0)
        need(permissions != 0, 'mapping has no DMA permission')
        for index, pa in enumerate(row['physical'][:row['pages']]):
            addr = base + index * 4096
            need(pa > 0 and pa & 4095 == 0 and addr not in expected and addr != pa,
                 'invalid physical page, overlapping IOVA or identity mapping')
            # makeDefaultLeaf uses PR + FC, with no next-level encoding.
            expected[addr] = pa | permissions | (1 << 60) | 1
    actual, tables = leaves(value)
    need(actual == expected and len(actual) == m['livePages'],
         'whole active PT differs from the complete live-record set')
    need(len(rows) == m['liveCount'] and tables == 11, 'live count/table topology differs')
    return {'maps': len(rows), 'pages': len(actual), 'tables': tables, 'identityPages': 0}


def analyze(cap):
    checks, states = [], {}

    def check(name, function):
        try:
            detail = function()
            checks.append({'id': name, 'state': 'ok', 'detail': detail})
        except (OSError, ValueError, KeyError, IndexError, TypeError, struct.error) as exc:
            checks.append({'id': name, 'state': 'FAIL', 'detail': str(exc)})

    def result():
        return {'scope': 'r44-ordinary-per-device-iomapper',
                'ok': len(checks) == 9 and all(c['state'] == 'ok' for c in checks),
                'checks': checks, 'limitations': [
                    'One target NIC, ordinary MTU1500 traffic and one interface down/up.',
                    'Current domain remains active; ifdown retains 64 RX groups and 3 fixed mappings.',
                    'This run does not establish system-wide IOMapper, full PM, hot-unplug or multi-device support.']}

    def capture_identity():
        manifest = json.loads((cap / 'manifest.json').read_text())
        need(manifest['scope'] == 'r44' and not manifest['errors'], 'capture reports missing evidence')
        for name, wanted in manifest['files'].items():
            data = (cap / name).read_bytes()
            need(wanted == {'bytes': len(data), 'sha256': sha(data)}, 'capture hash differs: ' + name)
        source = json.loads((cap / 'source-ref.json').read_text())
        need(source['base_commit'] == BASE_COMMIT and
             re.fullmatch('[0-9a-f]{40}', source['commit']) and source['commit'] != BASE_COMMIT,
             'source is not a recorded R44 successor')
        expected = json.loads((cap / 'expected-version.json').read_text())
        loaded = (cap / 'r44-version-confirmation.txt').read_text().lower()
        for name, version in VERSIONS.items():
            got = manifest['installed'][name]
            need(got['version'] == version and got['codesign_returncode'] == 0 and
                 all(got[key] == expected[name][key] for key in ('version', 'sha256', 'uuid')) and
                 got['uuid'].lower() in loaded and re.fullmatch('[0-9a-f]{64}', got['sha256']),
                 'installed/loaded binary identity differs: ' + name)
        driver = manifest['installed']['RTL812xLucy']
        need(driver['enableTSO4'] is False and driver['enableTSO6'] is False, 'TSO must remain off')
        boot = (cap / 'boot-args.txt').read_text().split()
        need([v for v in boot if v.startswith('amdiommu=')] == ['amdiommu=auto'],
             'this boot did not select ordinary auto mode')
        for label in PHASES:
            states[label] = read_snapshot(cap / 'snapshots' / label)
        return {'sourceCommit': source['commit'], 'versions': VERSIONS, 'snapshots': len(states)}
    check('capture-and-binary-identity', capture_identity)
    if len(states) != len(PHASES):
        return result()

    def startup():
        first = states['phase1']
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
          lambda: {label: mapping_tree(states[label]) for label in PHASES})

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
            detail[label] = {key: m[key] for key in ('mapOk', 'unmapOk', 'liveCount',
                                                    'livePages', 'peakMaps', 'peakPages')}
        first, last = states['phase1']['mapper'], states['pre-down']['mapper']
        need(last['mapOk'] - first['mapOk'] >= 8192 + 1024 and
             last['unmapOk'] > first['unmapOk'] and last['reusedAllocations'] > 0,
             'ordinary packet mapping/retirement/reuse was not exercised')
        return detail
    check('ordinary-mapping-retirement-and-reuse', lifecycle)

    client = (cap / 'client.log').read_text()
    peer = (cap / 'peer.log').read_text()
    token = int((cap / 'token.txt').read_text(), 0)

    def traffic():
        records = {}
        for text, names in ((client, ('client_sent', 'client_recv')), (peer, ('peer_recv', 'peer_sent'))):
            for name in names:
                found = [(i, line) for i, line in enumerate(text.splitlines()) if line.startswith(name + ' ')]
                ids = []
                for _, line in found:
                    match = re.match(name + r' token=(0x[0-9a-fA-F]+) req=(\d+) len=(\d+) '
                                     r'sha256=([0-9a-f]{64}) payload=([0-9a-f]+)(?: |$)', line)
                    need(match is not None, 'malformed traffic record: ' + name)
                    req, data = int(match[2]), bytes.fromhex(match[5])
                    need(int(match[1], 16) == token and data == P.payload(token, req) and
                         len(data) == int(match[3]) and sha(data) == match[4], 'traffic bytes differ')
                    if name.endswith('recv'):
                        need(' payload_ok=1 ' in line, 'received payload/source was rejected')
                    ids.append(req)
                need(len(ids) == len(P.REQUESTS) and set(ids) == set(P.REQUESTS),
                     name + ': missing/duplicate requests')
                for index, group in enumerate(P.bursts()):
                    need(set(ids[index * 16:(index + 1) * 16]) == set(group), 'request crossed burst boundary')
                if name == 'client_sent':
                    need(ids == list(P.REQUESTS), 'client did not send monotonically')
                records[name] = [(i, name.rsplit('_', 1)[1], req) for (i, _), req in zip(found, ids)]
        events = sorted(records['client_sent'] + records['client_recv'])
        for index in range(512):
            need([v[1] for v in events[index * 32:(index + 1) * 32]] == ['sent'] * 16 + ['recv'] * 16,
                 'burst did not send all 16 before receive')
        need(client.splitlines().count('client_summary sent=8192 acked=8192 bad=0') == 1 and
             client.splitlines().count('client_result OK') == 1 and
             not re.search(r'^client_(?:timeout|error|result FAIL)', client, re.M) and
             not re.search(r'^peer_tail', peer, re.M), 'success summary differs or tail/timeout present')
        return {'requests': 8192, 'groups': 512, 'groupSize': 16, 'retransmissions': 0}
    check('ordinary-8192-request-byte-integrity', traffic)

    def persistent():
        values = [identity(states[label]) for label in PHASES]
        need(all(v == values[0] and all(x > 0 for x in v) for v in values),
             'device domain was recreated across idle or interface down/up')
        times = [states[label]['mapper']['snapshotTime'] for label in PHASES]
        sequences = [states[label]['mapper']['snapshotSequence'] for label in PHASES]
        need(all(a < b for a, b in zip(times, times[1:])) and
             all(a < b for a, b in zip(sequences, sequences[1:])), 'snapshot order differs')
        begin = re.findall(r'^client_mapper_idle_begin seconds=125 t_ns=(\d+)$', client, re.M)
        end = re.findall(r'^client_mapper_idle_end t_ns=(\d+)$', client, re.M)
        need(len(begin) == len(end) == 1, 'one deliberate idle interval required')
        begin, end = int(begin[0]), int(end[0])
        need(end - begin >= 125_000_000_000 and times[0] < begin < end <= times[1], 'idle duration/order differs')
        before = re.search(r'^client_recv .* req=4096 .* t_ns=(\d+)$', client, re.M)
        after = re.search(r'^client_sent .* req=4097 .* t_ns=(\d+)$', client, re.M)
        need(before and after and int(before[1]) < begin and int(after[1]) >= times[1],
             'idle is not between the two 4096-request halves')
        return {'idleSeconds': (end - begin) / 1e9, 'sameDomain': True, 'identity': values[0]}
    check('same-domain-through-idle-and-normal-lifecycle', persistent)

    def ordinary():
        sets = {}
        for text, name in ((client, 'client_ord_sent'), (client, 'client_ord_recv'), (peer, 'peer_ord_recv')):
            records = []
            for line in text.splitlines():
                if not line.startswith(name + ' '):
                    continue
                match = re.match(name + r' seq=(\d+)(?: tag=(\S+))? len=(\d+) sha256=([0-9a-f]{64}) payload=([0-9a-f]+)', line)
                need(match is not None, 'malformed ordinary record')
                seq, data = int(match[1]), bytes.fromhex(match[5])
                need(data == P.ordinary(seq) and len(data) == int(match[3]) and sha(data) == match[4],
                     'ordinary probe bytes differ')
                if name.endswith('recv'):
                    need(' payload_ok=1 ' in line, 'ordinary receive rejected')
                records.append((seq, match[2]))
            need(len(records) == 1047 and len({v[0] for v in records}) == 1047,
                 'ordinary probes missing/duplicate')
            sets[name] = records
        need(sets['client_ord_sent'] == sets['client_ord_recv'] and
             {v[0] for v in sets['client_ord_recv']} == {v[0] for v in sets['peer_ord_recv']},
             'ordinary probe endpoints differ')
        tags = {tag: sum(v[1] == tag for v in sets['client_ord_recv']) for tag in ('pre', 'window', 'after-up')}
        need(tags == {'pre': 20, 'window': 1024, 'after-up': 3}, 'ordinary probe phase counts differ')
        return tags
    check('ordinary-probes-before-during-and-after-up', ordinary)

    def normal_lifecycle():
        before, down, after = (states[name] for name in ('pre-down', 'down', 'after-up'))
        bd, dd, ad = (v['driver'] for v in (before, down, after))
        need(dd['rtl812x-r44-state'] == 'disabled' and ad['rtl812x-r44-state'] == 'enabled' and
             dd['rtl812x-r44-disable-count'] == bd['rtl812x-r44-disable-count'] + 1 and
             ad['rtl812x-r44-enable-count'] > bd['rtl812x-r44-enable-count'], 'ordinary disable/enable events missing')
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
        need(all(v == fixed_handles['phase1'] for v in fixed_handles.values()), 'persistent fixed resources were recreated')
        need(not re.search(r'R31Stop|client_stop_begin', client), 'legacy experiment stop was used')
        return {'downLiveMaps': 67, 'rxGroups': 64, 'fixedMappings': 3,
                'enableCount': ad['rtl812x-r44-enable-count'], 'disableCount': dd['rtl812x-r44-disable-count']}
    check('ordinary-interface-down-up-with-retained-resources', normal_lifecycle)

    def hardware():
        for label, value in states.items():
            p, m = value['probe'], value['mapper']
            need(p['r44-target-faults'] == 0 and p['r44-event-overflow'] == 'no' and
                 p['r44-event-valid'] == 'yes' and p['r44-command-failed'] == 'no', label + ': hardware fault/event failure')
            need(p['r44-inv-dev-completed'] == 1 and p['r44-cmd-submits'] == p['r44-cmd-completed'] ==
                 p['r44-inv-pages-completed'] + 1 and p['r44-cmd-completion-sequence'] == p['r44-cmd-completed'],
                 label + ': command completion differs')
            need(p['r44-dte0'] & ADDRESS_MASK == m['rootPA'] and (p['r44-dte0'] >> 9) & 7 == 4 and
                 p['r44-dte0'] & 3 == 3 and p['r44-dte1'] & 65535 == p['r44-domain-id'],
                 label + ': active device table entry differs')
        last = states['after-up']['probe']
        need(last['r44-cmd-wraps'] > 0 and last['r44-cmd-post-wrap'] > 0, 'command ring did not pass wrap')
        return {'commandsCompleted': last['r44-cmd-completed'], 'wraps': last['r44-cmd-wraps'], 'targetFaults': 0}
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
