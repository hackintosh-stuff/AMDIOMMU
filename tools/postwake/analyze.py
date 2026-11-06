#!/usr/bin/env python3
"""Offline R67 acceptance: a verified wake, four sustained streams, then down/up."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import runpy

HERE = Path(__file__).resolve()
W = runpy.run_path(str(HERE.with_name('postwake.py')),
                   init_globals={'ROUND_ENTRY': globals().get('ROUND_ENTRY')})
C, T, PM = W['C'], W['T'], W['PM']
read, need = W['read'], W['need']


def journal(path):
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line]


def traffic(client, peers, config, token):
    plans = [r for r in client if r.get('event') == 'start']
    need(len(plans) == 1 and plans[0]['token'] == token and
         plans[0]['streams'] == 4 and 300 <= plans[0]['seconds'] <= 600,
         'not one bounded four-stream sustained run')
    seconds = plans[0]['seconds']
    for label, rows in [('client', client)] + list(peers.items()):
        done = [r for r in rows if r.get('event') == 'result']
        need(len(done) == 1 and done[0].get('ok') is True, label + ': incomplete/failed run')
    roles = C.roles(config)
    intervals, totals = [], {}
    for role in ('a', 'b'):
        totals[role] = {}
        for direction in ('upload', 'download'):
            def select(rows, event):
                return [r for r in rows if (r.get('event'), r.get('role'), r.get('direction'))
                        == (event, role, direction)]
            starts, dones = select(client, 'stream-start'), select(client, 'stream-done')
            ps, pd = select(peers[role], 'stream-start'), select(peers[role], 'stream-done')
            need(len(starts) == len(dones) == len(ps) == len(pd) == 1,
                 role + '/' + direction + ': missing/reconnected stream')
            start, end = starts[0], dones[0]
            endpoint = roles[role]
            need(start['interface'] == endpoint['interface'] and
                 start['requester'] == endpoint['requester'] and
                 start['ifindex'] == start['bound_ifindex'] > 0,
                 'stream was not bound to its selected NIC')
            for key, value in [('local', endpoint['local_ipv6']), ('peer', endpoint['peer_ipv6'])]:
                need(ipaddress.IPv6Address(start[key]['address']) ==
                     ipaddress.IPv6Address(value.split('%')[0]), 'selected IPv6 address differs')
            need(start['peer']['port'] == endpoint['port'], 'selected peer port differs')
            T['P'].validate_transport(ps[0], start)
            rows, receipts = select(client, 'block'), select(peers[role], 'block')
            need(len(rows) == len(receipts) == end['blocks'] == pd[0]['blocks'] and len(rows) >= 2,
                 role + '/' + direction + ': missing block receipts')
            previous_end = start['start_ns']
            for index, (row, receipt) in enumerate(zip(rows, receipts)):
                need(row['index'] == receipt['index'] == index and
                     row['run_token'] == receipt['run_token'] == token and
                     row['token'] == receipt['token'] == token + index and
                     row['bytes'] == receipt['bytes'] == T['BLOCK'] and
                     row['verified'] is receipt['verified'] is True and
                     row['sha256'] == row['expected_sha256'] == row['peer_sha256'] ==
                     receipt['sha256'] == receipt['expected_sha256'],
                     role + '/' + direction + ': payload/hash/sequence mismatch')
                need(len(row['sha256']) == 64 and all(x in '0123456789abcdef' for x in row['sha256']),
                     'invalid SHA256')
                need(row['local'] == start['local'] and row['peer'] == start['peer'] and
                     previous_end <= row['start_ns'] < row['end_ns'], 'connection/timeline changed')
                T['P'].validate_transport(receipt, row)
                previous_end = row['end_ns']
            need(rows[-1]['end_ns'] - start['start_ns'] >= seconds * 1_000_000_000,
                 role + '/' + direction + ': active stream window is too short')
            need(end['bytes'] == pd[0]['bytes'] == len(rows) * T['BLOCK'] and
                 end['end_ns'] >= previous_end and end['token'] == pd[0]['token'] == token,
                 'final byte count differs')
            intervals.append((rows[0]['start_ns'], rows[-1]['end_ns']))
            totals[role][direction] = {'bytes': end['bytes'], 'blocks': len(rows),
                'seconds': (rows[-1]['end_ns'] - rows[0]['start_ns']) / 1e9}
    overlap = (min(e for _, e in intervals) - max(s for s, _ in intervals)) / 1e9
    need(overlap >= seconds - 1, 'four streams did not overlap for the sustained window')
    return {'four_stream_overlap_seconds': overlap, 'bytes': sum(
        v['bytes'] for r in totals.values() for v in r.values()), 'streams': totals,
        'reconnections': 0, 'block_bytes': T['BLOCK']}


def analyze(out):
    checks, context = [], {}

    def check(name, action):
        try:
            checks.append({'id': name, 'ok': True, 'detail': action()})
        except (OSError, ValueError, RuntimeError, KeyError, TypeError, IndexError) as exc:
            checks.append({'id': name, 'ok': False, 'detail': str(exc)})

    def evidence():
        manifest = read(out / 'manifest.json')
        need(manifest['scope'] == W['SCOPE'], 'wrong evidence scope')
        for path, record in manifest['files'].items():
            file = out / path
            need(file.is_file() and file.stat().st_size == record['bytes'] and
                 W['sha'](file) == record['sha256'], 'evidence hash differs: ' + path)
        binding = read(out / 'binding.json')
        need(binding['kernel_rebuilt'] is False and binding['token'] == W['ENTRY']['RUN'].token,
             'not the retained R66-2 runtime')
        for label, digest in binding['origin_sha256'].items():
            need(W['sha'](out / 'provenance' / label / 'state.json') == digest, 'PM origin differs')
        before = read(out / 'provenance/pm-before/state.json')
        after = read(out / 'provenance/pm-after/state.json')
        need(PM['analyze'](before, after)['ok'], 'origin PM cycle failed')
        expected = read(out / 'provenance/expected-version.json')
        for label in ('identity-start', 'identity-end'):
            identities = read(out / label / 'installed.json')
            loaded = (out / label / (W['IDENTITY_SCOPE'] + '-version-confirmation.txt')).read_text(encoding='utf-8').lower()
            for name, version in W['ENTRY']['RUN'].versions.items():
                row = identities[name]
                need(row['version'] == version and row['codesign_returncode'] == 0 and
                     all(row[k] == expected[name][k] for k in ('version', 'uuid', 'sha256')) and
                     row['uuid'].lower() in loaded, 'runtime build differs: ' + name)
        context.update(binding=binding, origin=after, config=C.configuration(out / 'endpoints.json'))
        return {'origin_pm_passed': True, 'kernel_rebuilt': False, 'manifest_files': len(manifest['files'])}

    def continuity():
        states = {name: read(out / name / 'state.json')
                  for name in ('attached', 'steady-before', 'steady-after', 'final')}
        for name, state in states.items():
            W['assert_same_wake'](context['origin'], state)
            W['assert_same_wake'](states['attached'], state)
            need(all(d['probe']['r66-pm-armed'] == 'no' for d in state['devices'].values()),
                 'PM was rearmed inside the traffic test')
        first, last = states['steady-before'], states['steady-after']
        progress = {}
        for role in ('a', 'b'):
            a, b = first['devices'][role], last['devices'][role]
            prefix = C.profile_for_state(a)['prefix']
            for k in ('enable-count', 'disable-count'):
                need(a['driver'][prefix + k] == b['driver'][prefix + k],
                     role + ': NIC restarted during continuous traffic')
            need(a['probe']['r63-park-count'] == b['probe']['r63-park-count'] and
                 a['probe']['r63-restore-count'] == b['probe']['r63-restore-count'],
                 role + ': permissions cycled during continuous traffic')
            p, q = a['probe'], b['probe']
            need(q['r44-map-ok'] > p['r44-map-ok'] and q['r44-unmap-ok'] > p['r44-unmap-ok'] and
                 p['r44-live-maps'] == q['r44-live-maps'] and
                 p['r44-live-pages'] == q['r44-live-pages'], role + ': mapping progress/retirement differs')
            progress[role] = {key: q[key] - p[key] for key in ('r44-map-ok', 'r44-unmap-ok')}
        for role in ('a', 'b'):
            if C.profile_for_state(first['devices'][role])['pm_prefix'] == 'rtl8111-r66_2-':
                need(last['devices'][role]['driver']['rtl8111-r66_2-restart-count'] ==
                     first['devices'][role]['driver']['rtl8111-r66_2-restart-count'],
                     'watchdog recovery occurred in the sustained window')
        need(last['controller']['r52-controller-cmd-wraps'] >
             first['controller']['r52-controller-cmd-wraps'], 'no command ring wrap under traffic')
        context['states'] = states
        return {'same_wake_through_final': True, 'target_faults': 0, 'mapping_deltas': progress}

    def streams():
        client = journal(out / 'steady/client.log')
        peers = {r: journal(out / ('steady/peer-' + r + '.log')) for r in ('a', 'b')}
        result = traffic(client, peers, context['config'], context['binding']['token'])
        states = context['states']
        begins = [r['start_ns'] for r in client if r.get('event') == 'stream-start']
        ends = [r['end_ns'] for r in client if r.get('event') == 'stream-done']
        need(states['steady-before']['monotonic_ns'] <= min(begins) <= max(ends) <=
             states['steady-after']['monotonic_ns'], 'traffic not between live checkpoints')
        return result

    def lifecycle():
        native = C.module('_r67_native_analysis', 'tools/dual/analyze.py')
        result = native.analyze(out / 'lifecycle-capture')
        need(result['ok'], 'native 96 MiB/down-up analysis failed: ' + json.dumps(result['checks']))
        context['native'] = result
        return result

    def bridge():
        cap = out / 'lifecycle-capture'
        run = read(cap / 'run.json')
        need(run['token'] == context['binding']['token'], 'native lifecycle token differs')
        # time.monotonic_ns() bases are per-process on this host, so client
        # timestamps from two different processes cannot be compared. Order
        # the native cycle after the sustained window by the domain command
        # counters instead: the lifecycle before-snapshot must already include
        # every mapping the sustained window created.
        for role in ('a', 'b'):
            snapshot = read(cap / 'snapshots/before' / role / 'snapshot.json')
            attached = context['states']['attached']['devices'][role]['probe']
            steady_after = context['states']['steady-after']['devices'][role]['probe']
            need(snapshot['probe']['r44-map-ok'] >= steady_after['r44-map-ok'] and
                 snapshot['probe']['r44-unmap-ok'] >= steady_after['r44-unmap-ok'],
                 'native down/up was not performed after sustained traffic')
            for key in ('r52-mapper-id', 'r44-root-pa', 'r66_2-pm-suspends', 'r66_2-pm-resumes',
                        'r66_2-pm-resume-pages-cw'):
                need(snapshot['probe'][key] == attached[key], 'native cycle used a different restored domain')
            last = read(cap / 'snapshots/b-after-up' / role / 'snapshot.json')
            final = context['states']['final']['devices'][role]
            prefix = C.profile_for_state(final)['prefix']
            for key in ('enable-count', 'disable-count'):
                need(last['driver'][prefix + key] == final['driver'][prefix + key],
                     'another NIC restart followed the accepted native cycle')
        return {'continuous_then_native_cycle': True, 'native_bytes': 96 << 20}

    check('wake-origin-and-runtime-builds', evidence)
    if checks[-1]['ok']:
        check('same-restored-domains-and-mapping-progress', continuity)
        if checks[-1]['ok']:
            check('four-persistent-ipv6-streams-and-dual-end-hashes', streams)
        check('postwake-96mib-reciprocal-down-up', lifecycle)
        if context.get('states') and context.get('native'):
            check('continuous-to-lifecycle-evidence-chain', bridge)
    return {'scope': W['ENTRY'].get('RESULT_SCOPE', 'r67-postwake-sustained-traffic'),
            'ok': len(checks) == 5 and all(r['ok'] for r in checks), 'checks': checks,
            'limits': 'One wake lineage; no multi-sleep stress test or peak-throughput claim.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('out')
    parser.add_argument('--json')
    args = parser.parse_args()
    result = analyze(C.project_path(args.out))
    if args.json:
        W['write'](C.project_path(args.json), result)
    print(json.dumps(result, indent=2))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
