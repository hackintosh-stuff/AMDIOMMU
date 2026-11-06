#!/usr/bin/env python3
"""Round25: full 512-request logs/counters, bounded retained-32 DMA evidence.

Does NOT claim 512 per-generation PTE proofs: only the retained 32 lifecycles
are available. Old analyze.py's full-history assertions remain unchanged.
"""
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import types
import analyze as A
from protocol import BURST, REQUESTS, bursts, payload

SCOPE = 'round25-512-application-and-cumulative-standard-path; retained32-only-PTE-lifecycles'
DOMAIN_VERSION, DOMAIN_HEADER, DOMAIN_RECORD_BYTES = 3, 80, 720
HISTORY_CAPACITY = 32
TAIL = DOMAIN_HEADER + HISTORY_CAPACITY * DOMAIN_RECORD_BYTES
DOMAIN_BYTES = TAIL + 72
DRIVER_VERSION, DRIVER_BYTES = 5, A.DRIVER_HEADER + HISTORY_CAPACITY * A.DRIVER_RECORD_BYTES
STD_VERSION, STD_BYTES = 4, A.STD_HEADER + HISTORY_CAPACITY * A.STD_RECORD_BYTES
# Snapshot.commandCapacity and m2-3b-command-capacity count 16-byte entries;
# M23_CMD_BUF_SIZE in the producer counts bytes. Do not compare unlike units.
COMMAND_RING_BYTES, COMMAND_ENTRY_BYTES = 8192, 16
COMMAND_CAPACITY = COMMAND_RING_BYTES // COMMAND_ENTRY_BYTES


def decode_domain(blob):
    A.need(len(blob) == DOMAIN_BYTES, 'domain v3 size must be %d' % DOMAIN_BYTES)
    h = A.unpack('version bytes count flags iovaBase iovaBytes rootPA leafPA '
                 'ptBase ptBytes rootLevel devid domid active', '4I6Q4I', blob)
    A.need(h['version'] == DOMAIN_VERSION and h['bytes'] == len(blob), 'domain v3 ABI missing')
    h.update(A.unpack('historyTotal historyStart mapsTotal retiresTotal '
                      'commandCapacity commandSubmits commandCompleted commandWraps '
                      'commandPostWrapCompleted liveOwners slotsUsed maxLiveOwners '
                      'slotUse0 slotUse1 slotUse2 slotUse3 completionSequence', '16IQ', blob, TAIL))
    rows = []
    for i in range(HISTORY_CAPACITY):
        at = DOMAIN_HEADER + i * DOMAIN_RECORD_BYTES
        r = A.unpack('handle tMapPublish tMapInv tClearPublish tRetireInv count '
                     'pages token req status maplen', '5Q6I', blob, at)
        r['segments'] = [A.unpack('pa bytes iova', '3Q', blob, at + 64 + j * 24) for j in range(8)]
        for j, key in enumerate(('physical', 'mapPte', 'clearPte')):
            r[key] = struct.unpack_from('<16Q', blob, at + 256 + j * 128)
        r['mapCommand'] = A.cmdrec(blob, at + 640)
        r['retireCommand'] = A.cmdrec(blob, at + 680)
        rows.append(r)
    return h, rows


def decode_std(blob):
    # Reuse the unchanged record decoder with its version constant scoped to
    # this call; never mutate analyze.py globals or its legacy full-history gate.
    A.need(len(blob) == STD_BYTES, 'standard v4 snapshot size differs')
    decoder = types.FunctionType(A.decode_std.__code__, dict(A.__dict__, STD_VERSION=STD_VERSION))
    h, rows = decoder(blob)
    h['historyTotal'], h['historyStart'], h['highReqAccepts'] = h.pop('r0'), h.pop('r1'), h.pop('r2')
    return h, rows


def retained(h, rows, total_key):
    total, start, count = h[total_key], h['historyStart'], h['count']
    A.need(total == 512 and count == 32 and start == 480, 'expected total512/count32/start480')
    return [rows[seq % 32] for seq in range(start, total)]


def check(cap):
    checks = []
    def run(name, fn):
        try:
            detail = fn()
            checks.append({'id': name, 'state': 'ok', 'detail': detail})
        except (A.Refused, OSError, ValueError, KeyError, IndexError, struct.error) as exc:
            checks.append({'id': name, 'state': 'FAIL', 'detail': str(exc)})
    def result():
        return {'scope': SCOPE, 'ok': bool(checks) and all(c['state'] == 'ok' for c in checks),
                'checks': checks, 'limitations': ['No per-generation evidence for the 480 overwritten retirement records.',
                'Application logs prove bytes, cumulative counters prove standard-path totals; retained 32 prove PTE/lifecycle relations.']}
    try:
        _, _, P, blob = A.read_capture(cap)
        dh, dom = decode_domain(blob('m2-3b-domain-raw', 'r21-domain-raw.bin'))
        gh, drv = A.decode_driver(blob('rtl812x-txmap-raw', 'r21-driver-raw.bin'))
        gh['historyStart'] = gh.pop('reserved')
        A.need(gh['version'] == DRIVER_VERSION and len(drv) == HISTORY_CAPACITY and gh['bytes'] == DRIVER_BYTES,
               'native v5 ABI missing')
        sh, std = decode_std(blob('rtl812x-txmap-std-raw', 'r21-std-raw.bin'))
        bh = A.decode_block(blob('rtl812x-txmap-block-raw', 'r21-block-raw.bin'))
        pt = blob('m2-3b-pt-raw', 'r21-pt-raw.bin')
        client = (cap / 'client.log').read_text(encoding='utf-8')
        peer = (cap / 'peer.log').read_text(encoding='utf-8')
        driver = (cap / 'driver-obs.txt').read_text(encoding='utf-8')
        token = gh['token']
        A.need(0 < token < 0x80000000 and sh['token'] == bh['token'] == token,
               'inconsistent/non-low-half token')
        A.need(dh['devid'] == gh['bdf'] == sh['bdf'] == bh['bdf'], 'capture device association differs')
        checks.append({'id': 'capture-ABI-domain3-native5-std4', 'state': 'ok'})
    except (A.Refused, OSError, ValueError, KeyError, IndexError, struct.error) as exc:
        checks.append({'id': 'capture-ABI-domain3-native5-std4', 'state': 'FAIL', 'detail': str(exc)})
        return result()

    def logs():
        records = {}
        for text, names in ((client, ('client_sent', 'client_recv')),
                            (peer, ('peer_recv', 'peer_sent'))):
            for name in names:
                lines = [(i, line) for i, line in enumerate(text.splitlines())
                         if line.startswith(name + ' ')]
                ids = []
                for _, line in lines:
                    m = re.match(name + r' token=(0x[0-9a-fA-F]+) req=(\d+) len=(\d+) '
                                 r'sha256=([0-9a-f]{64}) payload=([0-9a-f]+)(?: |$)', line)
                    A.need(m is not None, 'malformed ' + name)
                    tok, req, size, sha, data = int(m[1], 16), int(m[2]), int(m[3]), m[4], bytes.fromhex(m[5])
                    A.need(tok == token and data == payload(token, req) and len(data) == size and
                           hashlib.sha256(data).hexdigest() == sha, 'invalid bytes/hash/token: ' + name)
                    if name in ('peer_recv', 'client_recv'):
                        A.need(re.search(r'(?:^| )payload_ok=1(?: |$)', line) is not None,
                               name + ': payload/source was rejected')
                    ids.append(req)
                A.need(len(ids) == len(REQUESTS) and set(ids) == set(REQUESTS),
                       name + ': missing or duplicate requests')
                if name == 'client_sent':
                    A.need(ids == list(REQUESTS), 'client sends are not monotonic')
                else:
                    # UDP receives/echoes may permute inside a burst. The client
                    # must finish that burst before admitting the next one.
                    for i, group in enumerate(bursts()):
                        A.need(set(ids[i * BURST:(i + 1) * BURST]) == set(group),
                               name + ': request crossed a burst boundary')
                records[name] = [(at, name.rsplit('_', 1)[1], req)
                                 for (at, _), req in zip(lines, ids)]
        client_lines = client.splitlines()
        A.need([line for line in client_lines if line.startswith('client_summary ')] ==
               ['client_summary sent=512 acked=512 bad=0'] and
               [line for line in client_lines if line.startswith('client_result ')] == ['client_result OK'],
               'client success summary missing')
        A.need(not any(line.startswith('client_timeout ') for line in client_lines),
               'controlled request timed out')
        events = sorted(records['client_sent'] + records['client_recv'])
        A.need(len(events) == 1024, 'unexpected event count')
        markers = [(i, line) for i, line in enumerate(client_lines) if line.startswith('client_burst ')]
        A.need(len(markers) == len(bursts()), 'expected 32 groups')
        for i, requests in enumerate(bursts()):
            group = events[i * 2 * BURST:(i + 1) * 2 * BURST]
            A.need([e[1] for e in group] == ['sent'] * BURST + ['recv'] * BURST,
                   'group not all16 send-before-receive')
            at, marker = markers[i]
            A.need(marker == 'client_burst reqs=' + ','.join(map(str, requests)) and
                   (i == 0 or events[i * 2 * BURST - 1][0] < at) and at < group[0][0],
                   'burst declaration or position differs')
        peer_events = sorted(records['peer_recv'] + records['peer_sent'])
        for i in range(len(REQUESTS)):
            recv, sent = peer_events[2 * i:2 * i + 2]
            A.need(recv[1] == 'recv' and sent[1] == 'sent' and recv[2] == sent[2],
                   'peer echo was not paired with its validated receive')
        return {'requests': 512, 'groups': 32, 'groupSize': 16, 'duplicates': 0,
                'receiveOrder': 'permutation within each group only'}
    run('full512-bytes-no-retry-no-duplicate-credit', logs)

    def counters():
        for h, keys in ((dh, ('mapsTotal', 'retiresTotal', 'historyTotal')),
                        (sh, ('accepts', 'unmaps', 'historyTotal')), (gh, ('retired',))):
            A.need(all(h[k] == 512 for k in keys), 'cumulative512 mismatch: ' + str({k: h[k] for k in keys}))
        A.need(P['m2-3c-mode'] == 'standard-iomapper' and 'native-mbuf-standard-iomapper-v1' in driver,
               'standard mode missing')
        for key in ('m2-3c-map-calls', 'm2-3c-map-ok', 'm2-3c-unmap-ok', 'm2-3b-map-accepted', 'm2-3b-retires'):
            A.need(P[key] == 512, key + ' !=512')
        for key in ('m2-3c-insert-calls', 'm2-3c-map-rejects', 'm2-3b-map-rejected'):
            A.need(P[key] == 0, key + ' !=0')
        A.need(not any(sh[k] for k in ('rejects', 'unsupported', 'pinned')) and
               not any(gh[k] for k in ('dropped', 'rejected')), 'driver fallback/refusal/pin')
        A.need(sh['highReqAccepts'] == 480, 'missing high-request standard accepts480')
        return {'standardAccepts': 512, 'standardHighReqAccepts': 480, 'standardUnmaps': 512, 'retired': 512}
    run('cumulative512-standard-path-beyond32-no-fallback', counters)

    def geometry():
        A.need(dh['iovaBase'] == A.K_BASE and dh['iovaBytes'] == 16 * 4096, 'window geometry changed')
        A.need(dh['slotsUsed'] == 15 and all(dh['slotUse%d' % i] > 0 for i in range(4)), 'not all four slots used')
        A.need(dh['maxLiveOwners'] == gh['maxHeld'] == sh['maxHeld'] == 4, 'four-slot peak missing')
        vals = {}
        for key in ('R24TxWaits', 'R24TxResumes', 'R24TxWakes', 'R24TxPending'):
            m = re.search(r'"' + key + r'" = (\d+)', driver)
            A.need(m is not None, 'missing ' + key)
            vals[key] = int(m[1])
        A.need(all(vals[k] > 0 for k in ('R24TxWaits', 'R24TxResumes', 'R24TxWakes')) and vals['R24TxPending'] == 0,
               'backpressure/resume counters invalid')
        return vals
    run('fixed-four-slots-and-automatic-backpressure-resume', geometry)

    def commands():
        A.need(dh['commandCapacity'] == COMMAND_CAPACITY and dh['commandWraps'] >= 2 and
               dh['commandPostWrapCompleted'] > 0, 'original command ring wrap evidence missing')
        A.need(dh['commandSubmits'] == dh['commandCompleted'] == dh['completionSequence'] and
               dh['commandCompleted'] >= 1024,
               'commands not completely acknowledged')
        # Every m2b2Submit publishes a command/CompletionWait pair; the context
        # starts at slot zero. Keep the latest producer's exact wrap accounting.
        A.need(dh['commandWraps'] == dh['commandSubmits'] * 2 // dh['commandCapacity'] and
               dh['commandPostWrapCompleted'] == dh['commandCompleted'] - (dh['commandCapacity'] // 2 - 1),
               'wrap/post-wrap counters disagree with original-capacity pair submission')
        A.need(dh['commandCompleted'] >= dh['mapsTotal'] + dh['retiresTotal'] and
               dh['commandPostWrapCompleted'] <= dh['commandCompleted'],
               'command totals cannot cover the map and retire invalidations')
        for key, prop in (('commandCapacity', 'm2-3b-command-capacity'),
                          ('commandSubmits', 'm2-3b-submits'),
                          ('commandCompleted', 'm2-3b-command-completed'),
                          ('commandWraps', 'm2-3b-command-wraps'),
                          ('commandPostWrapCompleted', 'm2-3b-command-post-wrap-completed'),
                          ('completionSequence', 'm2-3b-completion-sequence')):
            A.need(P[prop] == dh[key], 'command raw/property mismatch: ' + prop)
        return dict({k: dh[k] for k in ('commandCapacity', 'commandSubmits', 'commandCompleted', 'commandWraps',
                                       'commandPostWrapCompleted', 'completionSequence')},
                    commandCapacityUnit='16-byte entries', commandRingBytes=COMMAND_RING_BYTES)
    run('original8192-command-ring-wraps-and-postwrap-completion', commands)

    def histories():
        dd = retained(dh, dom, 'historyTotal')
        gg = retained(gh, drv, 'retired')
        ss = retained(sh, std, 'historyTotal')
        # Retirement order is not issue/request order with four live mappings.
        # Match standard/backend by real mapper handle, native by token/request.
        # Standard mode stamps stdW.handle, not current.request.handle (native
        # handle remains zero). Never infer handle from ring position/request ID.
        for rows in (gg, ss):
            ids = {r['req'] for r in rows}
            A.need(len(ids) == 32 and ids <= set(REQUESTS), 'invalid/duplicate retained requests')
        for rows in (dd, ss):
            A.need(all(r['handle'] > 0 for r in rows) and len({r['handle'] for r in rows}) == 32,
                   'duplicate or zero retained standard/backend handles')
        A.need({r['handle'] for r in dd} == {r['handle'] for r in ss},
               'retained histories disagree on completed handles')
        A.need(all(r['handle'] == 0 for r in gg), 'unexpected native handle in standard mode')
        domains = {r['handle']: r for r in dd}
        drivers = {(r['token'], r['req']): r for r in gg}
        A.need(len(drivers) == 32 and set(drivers) == {(r['token'], r['req']) for r in ss},
               'retained native/standard token/request sets differ')
        intervals = []
        for w in ss:
            d, g = domains[w['handle']], drivers[(w['token'], w['req'])]
            A.need(g['tMap'] == w['tPrepared'], 'native/standard prepare stamp differs')
            req = w['req']
            # IOMapper sees no packet/request metadata. Domain rows deliberately
            # carry zero req/token; match them to packet witnesses by issued handle.
            A.need(d['req'] == d['token'] == 0 and g['req'] == req and
                   g['token'] == w['token'] == token,
                   'retained handle/request/token association differs')
            A.need(g['version'] == 5 and w['version'] == 4 and w['flags'] == 3 and d['status'] == 3 and
                   g['retired'] == 1 and w['memory'] and w['command'], 'incomplete standard lifecycle')
            A.need(g['cumulative'] < g['doneClose'], 'close pointer did not pass retained generation')
            n = w['segCount']
            A.need(1 <= n <= 8 and n == d['count'] == g['count'] and 1 <= w['mbufSegments'] <= 8,
                   'segment geometry inconsistent')
            A.need(w['completeResult'] == w['prepareResult'] == w['segmentResult'] == 0, 'standard result not success')
            A.need(0 < d['tMapPublish'] <= d['tMapInv'] <= g['tOwn'] <= g['tDone'] <=
                   d['tClearPublish'] <= d['tRetireInv'] <= g['tFree'], 'map/OWN/completion/retire/free order')
            A.need(0 < w['tBegin'] <= w['tPrepared'] <= w['tSegmented'] <= w['tCommit'] and
                   0 < w['tCompleteBegin'] <= w['tCompleteEnd'] <= w['tFree'] == g['tFree'], 'standard object lifetime order')
            expect = {}
            for i in range(n):
                s, ws, gs = d['segments'][i], w['segments'][i], g['descriptors'][i]
                A.need(s['iova'] == ws['address'] == gs['address'] == g['iova'][i]['address'] and
                       s['bytes'] == ws['length'] == gs['length'] and s['pa'] != s['iova'], 'identity/fallback or run differs')
                # Standard mode does not export Request.physical (only the
                # direct mapper fills it). Real PA evidence is the backend's
                # segments/physical/PTE triple checked below, not this zero field.
                A.need(g['physical'][i]['address'] == g['physical'][i]['length'] == 0,
                       'unexpected native physical run in standard mode')
                A.need(g['doneOpts1'][i] & 0x80000000, 'descriptor not submitted')
                for k in range(((s['pa'] & 4095) + s['bytes'] + 4095) // 4096):
                    j = (s['iova'] - A.K_BASE) // 4096 + k
                    expect[j] = (s['pa'] & ~4095) + k * 4096
            A.need(len(expect) == d['pages'] and 1 <= d['pages'] <= 4 and
                   len({j // 4 for j in expect}) == 1 and all(0 <= j < 16 for j in expect), 'not one fixed stripe')
            intervals.append((d['tMapPublish'], d['tRetireInv'], next(iter(expect)) // 4))
            A.need(w['mapAddress'] == w['segments'][0]['address'] and d['maplen'] >= w['descriptorLength'],
                   'map address/unmap length invalid')
            for j, pa in expect.items():
                got, leaf = A.walk_with_leaf(pt, dh['rootPA'], dh['ptBase'], dh['leafPA'], dh['rootLevel'],
                                             A.K_BASE + j * 4096, d['mapPte'][j])
                A.need(got == pa == d['physical'][j] and leaf == d['mapPte'][j] and d['clearPte'][j] == 0,
                       'retained PTE mapping/clear differs')
            for key in ('mapCommand', 'retireCommand'):
                c = d[key]
                A.need(c['expected'] > 0 and c['expected'] == c['observed'] and c['tComplete'] > 0, 'CompletionWait mismatch')
                A.need(c['words'] == [0, dh['domid'] | (3 << 28), 0xfffff003, 0x7fffffff],
                       'not full-domain PDE-inclusive invalidation')
            A.need(d['mapCommand']['expected'] < d['retireCommand']['expected'] <= dh['completionSequence'] and
                   d['mapCommand']['tComplete'] == d['tMapInv'] and
                   d['retireCommand']['tComplete'] == d['tRetireInv'], 'completion order/timestamps differ')
            A.need(w['descriptorLength'] == sum(s['length'] for s in w['segments'][:n]) > len(payload(token, req)),
                   'frame/run byte mismatch')
        for start, end, stripe in intervals:
            for start2, end2, stripe2 in intervals:
                if start < start2 < end:
                    A.need(stripe != stripe2, 'live retained generations share a stripe')
        timeline = sorted([(start, 1) for start, _, _ in intervals] + [(end, -1) for _, end, _ in intervals])
        live = peak = 0
        for _, delta in timeline:
            live += delta
            peak = max(peak, live)
        A.need(1 < peak <= 4, 'retained mappings do not show bounded overlap')
        return {'peakRetainedLive': peak, 'retained': 32, 'requests': sorted(r['req'] for r in ss), 'correlation': 'standard/backend nonzero handle; native token+request, prepare/free stamps, segments/descriptors',
                'handles': sorted(domains), 'nativeHandles': sorted({g['handle'] for g in gg}),
                'overwrittenNotIndividuallyProved': 480}
    run('retained32-standard-handles-PTE-and-retirement-lifecycles', histories)

    def exit_state():
        A.need(dh['liveOwners'] == dh['active'] == dh['flags'] == sh['pinned'] == 0 and P['m2-3b-owners-held'] == 0,
               'live backend owner remains')
        A.need(bh['outstanding'] == bh['liveCount'] == bh['liveHandle'] == bh['state'] == 0 and
               not bh['liveFlags'] & 4 and bh['txDirty'] == bh['txNext'] and bh['txClose'] == bh['txTail'],
               'ring/driver not quiescent')
        A.need(bh['sampleStage'] == 3 and bh['sampleSeq'] > 0 and bh['quiesced'] == 1 and
               bh['activeCover'] == 0 and bh['ringBytes'] == 1024 * bh['ringDescSize'],
               'not actual exit ring sample')
        # Production exports total/new/raw events, not win-type2-count. Require
        # an empty, running, non-overflowed event log, not missing-field defaults.
        event_keys = ('m2-b2-win-entries', 'm2-b2-win-new-entries', 'm2-b2-win-raw-count',
                      'm2-b2-win-pre-backlog', 'm2-b2-win-devid-mismatch')
        for key in event_keys + ('m2-3c-cover-unconf',):
            A.need(P[key] == 0, 'fault/unconfirmed: ' + key)
        A.need(P['m2-b2-window-valid'] == 'yes' and P['m2-b2-win-raw-truncated'] == 'no',
               'invalid/truncated event window')
        positions = [P['m2-b2-win-' + k] for k in ('head-start', 'tail-start', 'head-end', 'tail-end')]
        A.need(len(set(positions)) == 1 and 0 <= positions[0] < 8192 and positions[0] % 16 == 0,
               'event ring not empty and unchanged')
        statuses = [P['m2-b2-win-status-' + k] for k in ('start', 'end')]
        # AMDMapperProbeInternal.hpp: overflow=bit0, event-log-running=bit3.
        A.need(all(not (status & 1) and (status & 8) for status in statuses),
               'event log overflowed or was stopped')
        return {'pending': 0, 'owners': 0, 'pinned': 0, 'ringOutstanding': 0, 'devicePageFaults': 0,
                'eventCounts': {k: P[k] for k in event_keys}, 'eventPositions': positions,
                'eventStatuses': statuses, 'rawTruncated': P['m2-b2-win-raw-truncated']}
    run('zero-pending-owners-pins-ring-and-no-device-page-fault', exit_state)

    def window():
        tokens = {'m2-3e-enter': 'gate-open-after-dte-and-invalidations', 'm2-3e-enter-drain': 'drained',
                  'm2-3e-exit-drain': 'drained', 'm2-3e-translate-off': 'confirmed-by-register-readback',
                  'm2-3e-exit-detach': 'detached', 'm2-3e-after-exit': 'ordinary-output-resumed',
                  'm2-3b-cleanup': 'detached-after-restore-confirmed'}
        for key, val in tokens.items():
            A.need(P[key] == val, 'window phase missing: ' + key)
        for key in ('m2-3e-enter-last-inflight', 'm2-3e-enter-last-ring', 'm2-3e-exit-last-inflight', 'm2-3e-exit-last-ring'):
            A.need(P[key] == 0, 'boundary not drained: ' + key)
        enter = [P[k] for k in ('m2-3e-enter-gate-close', 'm2-3e-enter-submit-done', 'm2-3e-enter-drain-done',
                                'm2-b2-dma-t-dte-written', 'm2-3e-t-translate-on', 'm2-3e-t-gate-open')]
        leave = [P[k] for k in ('m2-3e-exit-gate-close', 'm2-3e-exit-submit-done', 'm2-3e-exit-drain-done',
                                'm2-3e-t-translate-off', 'm2-3e-t-detach', 'm2-3e-t-resume')]
        A.need(all(t > 0 for t in enter + leave) and enter == sorted(enter) and leave == sorted(leave) and enter[-1] < leave[0],
               'window entry/exit timestamps out of order')
        for rows in (drv, std):
            for r in rows:
                A.need(enter[-1] <= r.get('tOwn', r.get('tBegin', 0)) <= r['tFree'] <= leave[2],
                       'retained generation outside same window')
        return {'entry': enter, 'exit': leave, 'domain': dh['domid'], 'device': dh['devid']}
    run('same-domain-window-enter-and-exit-order', window)

    def ordinary():
        records = A._ord_records(client)
        oks = [r for r in records if r['kind'] == 'recv' and r.get('ok') == 1]
        before = [r for r in oks if r['tag'] == 'pre' and 0 < r['t'] < P['m2-3e-enter-gate-close']]
        during = [r for r in oks if r['tag'] == 'window' and P['m2-3e-t-translate-on'] <= r['t'] <= P['m2-3e-exit-gate-close']]
        after = [r for r in oks if r['tag'] == 'after-exit' and r['t'] > P['m2-3e-t-resume']]
        seen = {r['seq'] for r in A._ord_records(peer) if r['kind'] == 'recv'}
        A.need(before and during and len(after) >= 3 and all(r['seq'] in seen for r in after), 'ordinary before/window/after evidence missing')
        return {'before': len(before), 'during': len(during), 'after': len(after)}
    run('ordinary-traffic-before-during-and-three-after', ordinary)
    return result()


if __name__ == '__main__':
    report = check(Path(sys.argv[1]))
    text = json.dumps(report, indent=2) + '\n'
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text(text, encoding='utf-8')
    else:
        print(text)
    raise SystemExit(0 if report['ok'] else 1)
