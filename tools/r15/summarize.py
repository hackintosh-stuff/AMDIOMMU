#!/usr/bin/env python3
"""Print concise raw-linked facts from one final R15 RX report and its capture."""
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location('r15_summary_decode', Path(__file__).with_name('analyze.py'))
A = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(A)


def main():
    report_path, capture = Path(sys.argv[1]), Path(sys.argv[2])
    report = json.loads(report_path.read_text(encoding='utf-8'))
    d = report['details']
    print('REPORT', report_path, 'RX_ONLY_OK', report['ok'])
    print('FAILED_CHECKS', [r['id'] for r in report['checks'] if r['state'] != 'ok'])
    print('ALLOCATIONS', json.dumps(d['allocation_policy'], sort_keys=True))
    for label in ('pool-before', 'pool-after', 'rxset'):
        item = d[label]
        print('RANGES', label, 'count', item['ranges'], 'ok', item['ok'],
              'bytes', item['bytes_total'], 'min', hex(item['min_addr']),
              'end', hex(item['max_end']), 'end_GiB', item['max_end'] / 2 ** 30)
    print('TIMELINE_NS', json.dumps(d['timeline_ns'], sort_keys=True))
    w = d['witnesses']
    print('WITNESSES', 'posted', w['posted'], 'completed', w['completed'],
          'pending', w['pending'], 'controlled_payload_proved', len(w['controlled']))
    _, entries, _ = A.decode_pool((capture / 'r15-pool-before-raw.bin').read_bytes())
    entry_by_id = {e['id']: e for e in entries}
    chosen, sources = [], set()
    for i in w['controlled']:
        source = entry_by_id[w['raw'][i]['entryId']]['reserved']
        if source not in sources:
            chosen.append(i)
            sources.add(source)
    for i in chosen:
        raw = w['raw'][i]
        proof = w['payload_log_proofs'][str(i)]
        print('REPRESENTATIVE', i, 'source', entry_by_id[raw['entryId']]['reserved'],
              'slot', raw['slot'], 'old', hex(raw['oldAddr']), 'new', hex(raw['newAddr']),
              'capacity', raw['capacity'], 'post_ticks', raw['tPost'], 'done_ticks', raw['tDone'],
              'token', hex(raw['token']), 'req', raw['reqId'], 'raw_frame_FCS', raw['doneLength'],
              'payload', proof['payload_bytes'], 'peer_lines', proof['peer_send_lines'],
              'mac_lines', proof['mac_receive_lines'])
    print('HIGH_OWNED', d['above_16gib_owned'], 'HIGH_CONTROLLED', d['above_16gib_controlled'])
    print('FAULTS', [{'raw': hex(f['raw_addr']), 'page': hex(f['addr']),
                      'device': hex(f['device']), 'in_pool': f['in_owned_pool'], 'why': f['why']}
                     for f in d['faults']])


if __name__ == '__main__':
    main()
