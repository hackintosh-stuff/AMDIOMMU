#!/usr/bin/env python3
"""Four mainline checks: identity, domains, bytes, and one independent lifecycle."""
import argparse
import ipaddress
import json
import re
import struct
from common import (BASE_COMMIT, MAX_MAP_PAGES, MAX_RUNS, OFF_PHASES, PHASES, PROFILES, RUN, VERSIONS,
                    configuration, module, project_path, protocol as P,
                    read_snapshot, roles, sha, validate_selector, write_json)

TREE = module('_r53_page_table_walker', 'tools/r44/analyze.py')
R50 = module('_r53_range_decoder', 'tools/r50/analyze.py')
need = TREE.need


def json_file(path):
    return json.loads(path.read_text(encoding='utf-8'))


def json_lines(path):
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]


def numeric_address(value):
    return str(ipaddress.IPv6Address(value.split('%', 1)[0]))


def expected_maps(value):
    profile = PROFILES[value['binding']['driver_class']]
    return profile['rx_groups'] + len(profile['fixed'])


def native_resources(value, phase):
    """Join each driver's native fixed/RX resources to the complete mapper walk."""
    profile = PROFILES[value['binding']['driver_class']]
    d, rows, prefix = value['driver'], value['live'], profile['prefix']
    need(d[prefix + 'mode'] == 'auto' and d[prefix + 'mapped-dma'] == 1 and
         d[prefix + 'rx-groups'] == profile['rx_groups'] and
         d[prefix + 'rx-slots'] == profile['rx_slots'] and
         d[prefix + 'fixed-mappings'] == len(profile['fixed']), 'native driver resource shape differs')
    enabled = d[prefix + 'state'] == 'enabled'
    fixed = {}
    for kind, length in profile['fixed'].items():
        iova = d[prefix + kind + '-iova']
        matched = [row for row in rows if row['mapAddress'] == iova and row['length'] == length]
        need(len(matched) == 1, 'native fixed DMA object is missing: ' + kind)
        fixed[kind] = matched[0]
        # RTL8111 tally is periodic: its mapped object is checked above, while
        # the register is observed without waiting for a statistics timer.
        if enabled and (kind != 'tally' or value['binding']['driver_class'] == 'RTL8125'):
            need(d[prefix + kind + '-register'] == iova, 'native DMA register differs: ' + kind)
    fixed_handles = {row['handle'] for row in fixed.values()}
    rx = [row for row in rows if row['handle'] not in fixed_handles]
    need(len(rx) == profile['rx_groups'] and
         all(row['pages'] == profile['rx_pages'] and row['length'] == profile['rx_pages'] * 4096
             for row in rx), 'native RX groups do not match live DMA records')
    if value['binding']['driver_class'] == 'RTL8111':
        need(d[prefix + 'rx-pages-per-group'] == profile['rx_pages'] and
             d[prefix + 'tx-mapped-active'] == 0 and
             d[prefix + 'chip-command'] & 12 == (12 if enabled else 0), 'RTL8111 DMA state differs')
        resources = value['driver_live']
        need(len(resources) == expected_maps(value), 'RTL8111 resource export is incomplete')
        for index, kind in enumerate(('tx', 'rx', 'tally'), 1):
            matched = [row for row in resources if row['kind'] == index]
            need(len(matched) == 1 and matched[0]['iova'] == fixed[kind]['mapAddress'] and
                 matched[0]['length'] == fixed[kind]['length'], 'RTL8111 fixed resource identity differs')
        groups = [row for row in resources if row['kind'] == 4]
        need(len(groups) == profile['rx_groups'] and
             {row['index'] for row in groups} == set(range(profile['rx_groups'])),
             'RTL8111 RX group indices differ')
        by_iova = {row['mapAddress']: row for row in rx}
        for group in groups:
            mapped = by_iova.get(group['iova'])
            need(mapped is not None and group['length'] == mapped['length'],
                 'RTL8111 RX resource uses a different DMA mapping')
            if enabled:
                for slot in range(profile['rx_pages']):
                    address = value['rx_addresses'][group['index'] * profile['rx_pages'] + slot]
                    need(address == group['iova'] + slot * 4096,
                         'RTL8111 RX descriptor is not its mapped group IOVA')
    result = {'driver': value['binding']['driver_class'], 'persistentMaps': expected_maps(value),
            'rxGroups': profile['rx_groups'], 'rxPagesPerGroup': profile['rx_pages'],
            'fixedIOVAs': {kind: row['mapAddress'] for kind, row in fixed.items()},
              'tallyRegister': d[prefix + 'tally-register']}
    if RUN.reciprocal:
        # Report the selected IOVA against the RX object's actual size. Under
        # fragmentation other objects may legitimately use the first-fit fallback.
        result['naturallyAlignedRxGroups'] = sum(
            row['mapAddress'] % (row['pages'] * 4096) == 0 for row in rx)
    return result


def exact_range_counts(p, m):
    batches = p['r50-inv-range-completed']
    desc, splits = p['r61-range-descriptors'], p['r61-split-batches']
    need(0 <= splits <= batches and desc >= batches + splits and (splits or desc == batches)
         and p['r50-inv-range-pages'] == p['r60-inv-range-covered-pages'], 'bad range batch totals')
    if splits:
        raw = bytes.fromhex(p['r61-split-commands-hex'])
        cursor, size = p['r61-split-address'], p['r61-split-bytes']
        end = cursor + size
        need(32 <= len(raw) <= 256 and len(raw) % 16 == 0 and
             m['iovaBase'] <= cursor < end <= m['iovaBase'] + m['iovaBytes'] and
             0 < p['r61-split-sequence'] <= p['r50-last-range-sequence'], 'bad split witness')
        for words in struct.iter_unpack('<4I', raw):
            start, length = R50.decode_range(words, p['r44-domain-id'])
            need(start == cursor, 'split batch gap or overlap')
            cursor += length
        need(cursor == end, 'split batch ended outside the requested boundary')
    return dict(rangeBatches=batches, rangeDescriptors=desc, splitBatches=splits)


def ring_window(first, last):
    """Successful reservations from either source; MMIO reads also include repeat polls."""
    def delta(name):
        key = 'r52-controller-cmd-' + name
        return last[key] - first[key]
    completed, hits = delta('completed'), delta('cached-batches')
    reads, wraps = delta('head-reads'), delta('wraps')
    need(0 < hits < completed and reads >= completed - hits and wraps > 0,
         'command ring did not exercise cached reservations and HEAD refresh across wrap')
    return dict(completedBatches=completed, cachedBatches=hits, refreshedBatches=completed - hits,
                mmioHeadReads=reads, wraps=wraps)


def requester_access(p, before, role, phase):
    if RUN.both_requester_access:
        park_phase, restore_phase = (('down', 'after-up') if role == 'a'
                                     else ('b-down', 'b-after-up'))
        parked = phase == park_phase
        progressed = phase in (park_phase, restore_phase)
    else:
        parked = role == 'a' and phase == 'down'
        progressed = role == 'a' and phase != 'before'
    permissions = (p['r44-dte0'] >> 61) & 3
    parks, restores = p['r63-park-count'], p['r63-restore-count']
    p0, r0 = before['r63-park-count'], before['r63-restore-count']
    need(p['r63-dma-parked'] == ('yes' if parked else 'no') and
         permissions == (0 if parked else 3) and
         parks - restores == int(parked) and
         parks - p0 == int(progressed) and
         restores - r0 == int(progressed and not parked) and
         (RUN.both_requester_access or role == 'a' or parks == restores == 0),
         phase + '/' + role + ': requester DMA access or transition counts differ')
    if progressed:
        devcw, pagecw = p['r63-last-dev-cw'], p['r63-last-pages-cw']
        need(0 < devcw and pagecw == devcw + 1 and pagecw <= p['r44-cmd-completed'],
             phase + ': requester access change missing completed device and domain fences')
    return dict(ir=permissions & 1, iw=permissions >> 1, parks=parks, restores=restores,
                deviceCW=p['r63-last-dev-cw'], pagesCW=p['r63-last-pages-cw'])


def analyze(cap):
    checks, states, controllers, phase_data, data = [], {}, {}, {}, {}

    def check(name, action):
        try:
            checks.append({'id': name, 'state': 'ok', 'detail': action()})
        except (OSError, ValueError, KeyError, IndexError, TypeError, struct.error, RuntimeError) as exc:
            checks.append({'id': name, 'state': 'FAIL', 'detail': str(exc)})

    def evidence():
        manifest, run = json_file(cap / 'manifest.json'), json_file(cap / 'run.json')
        config = configuration(cap / 'endpoints.json')
        need(run['config'] == config, 'run endpoint configuration differs')
        mode = run['mode']
        need(mode in ('auto', 'off') and manifest['scope'] == 'r%d' % RUN.number and
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
            if mode == 'auto':
                validate_selector(' '.join(boot), config)
        loaded = (cap / ('r%d-version-confirmation.txt' % RUN.number)).read_text().lower()
        if mode == 'auto':
            source, expected = json_file(cap / 'source-ref.json'), json_file(cap / 'expected-version.json')
            need(source['base_commit'] == BASE_COMMIT and source['commit'] != BASE_COMMIT and
                 re.fullmatch(r'[0-9a-f]{40}', source['commit']), 'not a recorded R%d successor' % RUN.number)
            for name, version in VERSIONS.items():
                got = manifest['installed'][name]
                need(got['version'] == version and got['codesign_returncode'] == 0 and
                     all(got[key] == expected[name][key] for key in ('version', 'sha256', 'uuid')) and
                     got['uuid'].lower() in loaded, 'installed/loaded identity differs: ' + name)
            need(all(manifest['installed']['RTL812xLucy'][name] is True for name in ('enableTSO4', 'enableTSO6')),
                 'Lucy offloads differ')
        else:
            got = manifest['installed']['RTL812xLucy']
            need(got['codesign_returncode'] == 0 and got['uuid'].lower() in loaded,
                 'baseline Lucy installed/loaded identity missing')
            # The unmodified RTL8111 may be injected from EFI, without an L/E file.
            found = re.search(r'com\.insanelymac\.realtekrtl8111\s+\(([^)\n]+)\)', loaded)
            need(found is not None, 'baseline RTL8111 is not present in kmutil loaded identity')
            data['baselineRTL8111Version'] = found.group(1)
        for phase in PHASES if mode == 'auto' else OFF_PHASES:
            phase_dir = cap / 'snapshots' / phase
            phase_data[phase] = json_file(phase_dir / 'phase.json')
            controllers[phase] = phase_data[phase]['controller']
            states[phase] = {role: (read_snapshot(phase_dir / role) if mode == 'auto' else
                                   json_file(phase_dir / role / 'snapshot.json')) for role in ('a', 'b')}
        return {'mode': mode, 'versions': {name: row.get('version') for name, row in manifest['installed'].items()},
                'sourceCommit': source['commit'] if mode == 'auto' else None,
                'phases': list(states), 'baselineRTL8111Version': data.get('baselineRTL8111Version')}

    def domains():
        details, stable = {}, {}
        for phase, devices in states.items():
            for role, value in devices.items():
                binding, endpoint = value['binding'], data['roles'][role]
                need(all(binding[key] == endpoint[key] for key in
                         ('name', 'interface', 'bdf', 'requester', 'vendor_id', 'device_id', 'driver_class')) and
                     binding['observed_requester'] == endpoint['requester'] and
                     binding['observed_vendor_id'] == int(endpoint['vendor_id'], 16) and
                     binding['observed_device_id'] == int(endpoint['device_id'], 16) and
                     binding['driver_registry_id'] > 0 and binding['pci_registry_id'] > 0,
                     phase + ': interface/PCI identity differs')
            need(len({v['binding']['driver_registry_id'] for v in devices.values()}) == 2,
                 'both endpoints selected the same Lucy instance')
            if data['mode'] == 'off':
                need(all(v['driver'].get(PROFILES[v['binding']['driver_class']]['prefix'] + 'mapped-dma', 0) == 0
                         for v in devices.values()),
                     'off baseline contains mapped DMA')
                details[phase] = {role: value['binding'] for role, value in devices.items()}
                continue
            controller = controllers[phase]
            need(controller['r52-domain-count'] == 2, 'shared controller must own the two selected domains')
            need(all(row['policy'] == 'passthrough' for row in phase_data[phase]['unselected_candidates']),
                 'an unselected candidate did not remain passthrough')
            trees, identities, leaves = {}, [], {}
            for role, value in devices.items():
                p, d, m = value['probe'], value['driver'], value['mapper']
                ip = PROFILES[value['binding']['driver_class']]['identity_prefix']
                need(value['binding']['dma_policy'] == 'mapped', 'selected PCI endpoint lacks mapped policy')
                if RUN.parent:
                    need(p.get('r44-parent') == RUN.parent,
                         phase + '/' + role + ': missing pre-open client claim for this mapper')
                ident = (p['r52-mapper-id'], p['r44-domain-id'], m['rootPA'])
                need(all(v > 0 for v in ident) and
                     p['r52-requester'] == p['r44-target-devid'] == value['binding']['requester'] and
                     d[ip + 'requester'] == p['r52-requester'] and
                     d[ip + 'mapper-id'] == ident[0] and d[ip + 'domain-id'] == ident[1] and
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
                trees[role] = TREE.mapping_tree(value, iova_base=0x80000000,
                                                 max_map_pages=MAX_MAP_PAGES, max_runs=MAX_RUNS)
                trees[role]['nativeResources'] = native_resources(value, phase)
                if RUN.parent:
                    trees[role]['bindingPath'] = p['r44-parent']
                leaves[role] = TREE.leaves(value)[0]
                if RUN.abi == 3 and value['binding']['driver_class'] == 'RTL8125':
                    # native_resources matched all eight 128-page RX groups; mapping_tree
                    # independently matched every expected PA to the entire active PT.
                    row = max(value['live'], key=lambda item: item['pages'])
                    last = row['pages'] - 1
                    iova = m['iovaBase'] + (row['basePage'] + last) * 4096
                    trees[role]['rxMapExample'] = dict(
                        pages=row['pages'], length=row['length'], mapAddress=row['mapAddress'],
                        lastPageIOVA=iova, expectedLastPA=row['physical'][last],
                        walkedLastPA=leaves[role][iova] & TREE.ADDRESS_MASK)
            need(all(identities[0][i] != identities[1][i] for i in range(3)),
                 'the devices share a mapper, domain ID, or page-table root')
            overlap = sorted(set(leaves['a']) & set(leaves['b']))
            examples = [{'iova': address, 'a_pa': leaves['a'][address] & TREE.ADDRESS_MASK,
                         'b_pa': leaves['b'][address] & TREE.ADDRESS_MASK}
                        for address in overlap[:4]]
            details[phase] = {'devices': trees, 'identities': identities,
                              'overlappingIOVAPages': len(overlap), 'independentWalkExamples': examples,
                              'unselectedCandidates': phase_data[phase]['unselected_candidates']}
        if RUN.reciprocal and data['mode'] == 'auto':
            for role in ('a', 'b'):
                need(any(phase['devices'][role]['nativeResources']['naturallyAlignedRxGroups']
                         for phase in details.values()),
                     role + ': no live RX group witnessed the preferred natural alignment')
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
        cycles = [('a', 'b', 'before', 'down', 'after-up', 'b-during-down', 'a-after-up')]
        if RUN.reciprocal:
            cycles.append(('b', 'a', 'after-up', 'b-down', 'b-after-up',
                           'a-during-b-down', 'b-after-up'))
        windows = []
        for target, other, pre, stopped, post, held_phase, recovery_phase in cycles:
            before, down, after = (states[phase] for phase in (pre, stopped, post))
            iface = data['roles'][target]['interface']
            for role in (target, other):
                prefix = PROFILES[before[role]['binding']['driver_class']]['prefix']
                b, d, a = [phase[role]['driver'] for phase in (before, down, after)]
                if role == target:
                    need(b[prefix + 'state'] == a[prefix + 'state'] == 'enabled' and
                         d[prefix + 'state'] == 'disabled' and
                         d[prefix + 'disable-count'] == b[prefix + 'disable-count'] + 1 and
                         a[prefix + 'enable-count'] == b[prefix + 'enable-count'] + 1 and
                         (not RUN.reciprocal or (d[prefix + 'enable-count'] == b[prefix + 'enable-count']
                          and a[prefix + 'disable-count'] == d[prefix + 'disable-count'])),
                         iface + ': selected target did not complete one ordinary down/up')
                else:
                    need(all(v[prefix + 'state'] == 'enabled' for v in (b, d, a)) and
                         len({v[prefix + 'disable-count'] for v in (b, d, a)}) == 1 and
                         len({v[prefix + 'enable-count'] for v in (b, d, a)}) == 1,
                         iface + ': other interface was reset during this down/up')
            events = {name: [row['time_ns'] for row in data['client']
                             if row.get('event') == name and row.get('interface') == iface]
                      for name in ('ifdown-done', 'ifup-requested')}
            need(all(len(v) == 1 for v in events.values()), iface + ': missing down/up window')
            begin, end = events['ifdown-done'][0], events['ifup-requested'][0]
            held = [row for row in data['transfers'] if row['phase'] == held_phase]
            recovered = [row for row in data['transfers'] if row['phase'] == recovery_phase]
            need(len(held) == 2 and all(begin < row['start_ns'] < row['end_ns'] < end for row in held)
                 and len(recovered) == 2 and all(end < row['start_ns'] for row in recovered),
                 iface + ': transfers did not occur during the down window and after recovery')
            need(down[other]['mapper']['mapOk'] > before[other]['mapper']['mapOk'] and
                 down[other]['mapper']['unmapOk'] > before[other]['mapper']['unmapOk'] and
                 after[target]['mapper']['mapOk'] > down[target]['mapper']['mapOk'],
                 iface + ': traffic did not exercise both domain map/unmap paths')
            if windows:
                need(windows[-1]['recoveryEndNS'] < begin, 'device down windows were not sequential')
            windows.append({'downRole': target, 'downInterface': iface, 'activeRole': other,
                            'activeInterface': data['roles'][other]['interface'],
                            'downNS': begin, 'upRequestedNS': end,
                            'heldBytes': sum(row['bytes'] for row in held),
                            'recoveryBytes': sum(row['bytes'] for row in recovered),
                            'recoveryEndNS': max(row['end_ns'] for row in recovered)})
        offloads = {}
        for role in ('a', 'b'):
            kind = states['before'][role]['binding']['driver_class']
            drivers = [phase[role]['driver'] for phase in states.values()]
            last = drivers[-1]
            if kind == 'RTL8125':
                tso = 'rtl812x-r46-tso6-'
                # Normal interface disable can retire a posted packet after the
                # hardware has stopped. Do not count stop reclamations as completions.
                need(last[tso + 'completed'] > drivers[0][tso + 'completed'] and
                     all(v[tso + 'posted'] == v[tso + 'completed'] +
                         (v[tso + 'stop-retired'] if RUN.reciprocal else 0) for v in drivers),
                     'Lucy IPv6 TSO work did not drain')
                offloads[role] = {'tso6Posted': last[tso + 'posted'], 'tso6Completed': last[tso + 'completed']}
                if RUN.reciprocal:
                    offloads[role]['tso6StopRetired'] = last[tso + 'stop-retired']
            else:
                offloads[role] = {'tso6CommandCalls': last[PROFILES[kind]['prefix'] + 'tso6-count']}
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
                expected_live = expected_maps(value)
                skipped = p['r51-map-invalidation-skipped']
                expected_skip = 0 if p['r51-npcache'] else m['mapOk'] - 1
                expected_inv = m['mapOk'] + m['unmapOk'] - skipped
                access, transitions = None, 0
                if RUN.requester_access:
                    access = requester_access(p, states['before'][role]['probe'], role, phase)
                    transition_prev = {
                        ('a', 'down'): 'before', ('a', 'after-up'): 'down',
                        ('b', 'b-down'): 'after-up', ('b', 'b-after-up'): 'b-down'}
                    previous_phase = transition_prev.get((role, phase))
                    if previous_phase is not None:
                        prev = states[previous_phase][role]['probe']
                        need(prev['r63-last-pages-cw'] < access['deviceCW'],
                             phase + ': permission change reused an earlier completion sequence')
                    transitions = access['parks'] + access['restores']
                need(p['r44-controller-ready'] == p['r44-dte-active'] == 'yes' and
                     p['r44-event-valid'] == 'yes' and
                     p['r51-npcache'] == ((p['r47-cap-header'] >> 26) & 1) and
                     m['flags'] == 3 and m['liveCount'] == expected_live and
                     m['mapCalls'] == m['mapOk'] and m['unmapCalls'] == m['unmapOk'] and
                     m['mapOk'] - m['unmapOk'] == expected_live and
                     m['mapRejected'] == m['unmapRejected'] == m['invalidateFailures'] == 0 and
                     skipped == expected_skip and m['invalidates'] == expected_inv and
                     p['r44-inv-pages-completed'] == expected_inv + transitions and
                     p['r52-domain-cmd-completed'] == expected_inv + 1 + 2 * transitions and
                     p['r50-inv-full-completed'] == 1 + transitions and
                     p['r50-inv-range-completed'] == expected_inv - 1 and
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
                    if RUN.exact_ranges:
                        need(m['iovaBase'] <= address <= start and start + size == address + requested
                             <= m['iovaBase'] + m['iovaBytes'], 'wrong final range in batch')
                    else:
                        need(m['iovaBase'] <= start <= address and
                             address + requested <= start + size <= m['iovaBase'] + m['iovaBytes'] and
                             requested > 0 and requested % 4096 == 0,
                             'last completed range does not cover this domain IOVA mapping')
                counters[role] = {'mapOk': m['mapOk'], 'unmapOk': m['unmapOk'],
                                  'mapSkipped': skipped, 'domainCommands': p['r52-domain-cmd-completed']}
                if RUN.reciprocal:
                    requested_pages = p['r50-inv-range-pages']
                    covered_pages = p['r60-inv-range-covered-pages']
                    need(covered_pages >= requested_pages >= p['r50-inv-range-completed'],
                         phase + '/' + role + ': range invalidation page totals differ')
                    counters[role].update(requestedPages=requested_pages, coveredPages=covered_pages)
                if access is not None:
                    counters[role]['requesterAccess'] = access
                if RUN.exact_ranges:
                    counters[role].update(exact_range_counts(p, m))
            details[phase] = {'controllerCommands': completed, 'devices': counters}
        if RUN.cached_ring_head:
            details['b-after-up']['ringWindow'] = ring_window(controllers['before'], controllers['b-after-up'])
        if RUN.exact_ranges:
            need(any(v['splitBatches'] for ph in details.values() for v in ph['devices'].values()),
                 'no multi-descriptor invalidation observed')
        result = {'otherDeviceTrafficWhileTargetDown': True, 'sameConnectionAcrossTransition': 'not tested',
                  'targetFaults': 0, 'counters': details, 'nativeOffloadCounters': offloads}
        if RUN.reciprocal:
            result['downWindows'] = windows
        return result

    check('capture-and-runtime-identity', evidence)
    expected_phases = PHASES if data.get('mode') == 'auto' else OFF_PHASES
    if len(states) == len(expected_phases):
        check('mixed-driver-resources-and-independent-domain-trees', domains)
        check('interface-bound-ipv6-and-dual-end-hashes', traffic)
        if 'client' in data:
            check('two-device-reciprocal-down-up-and-retirement' if RUN.reciprocal else
                  'one-device-down-other-device-business-and-retirement', lifecycle)
    return {'scope': 'r%d-mixed-drivers-shared-controller' % RUN.number, 'mode': data.get('mode'),
            'ok': len(checks) == 4 and all(row['state'] == 'ok' for row in checks), 'checks': checks,
            'limitations': [('One down/up per selected interface; the other carries traffic in each window.'
                             if RUN.reciprocal and data.get('mode') == 'auto' else
                             'One selected interface down/up; the other completes traffic while it is down.'),
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
