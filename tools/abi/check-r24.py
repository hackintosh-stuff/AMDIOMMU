#!/usr/bin/env python3
"""Add round24 continuous-send/backpressure checks to the unchanged r23 audit."""
import json
import re
import runpy
import sys
from pathlib import Path


def check(cap):
    result = runpy.run_path(str(Path(__file__).with_name('analyze.py')))['analyze'](cap)
    checks = result['checks']
    def add(name, ok, detail):
        checks.append({'id': name, 'state': 'ok' if ok else 'FAIL', 'detail': detail})
    lines = (cap / 'client.log').read_text().splitlines()
    events = []
    for i, line in enumerate(lines):
        m = re.match(r'client_(sent|recv) token=\S+ req=(\d+).* t_ns=(\d+)$', line)
        if m:
            events.append((m[1], int(m[2]), int(m[3]), i))
    sent = [e for e in events if e[0] == 'sent']
    recv = [e for e in events if e[0] == 'recv']
    add('r24-all16-sends-before-receive',
        [e[1] for e in sent] == list(range(1, 17)) and len(recv) == 16 and
        max(e[3] for e in sent) < min(e[3] for e in recv) and
        max(e[2] for e in sent) < min(e[2] for e in recv) and
        len([s for s in lines if s.startswith('client_burst ')]) == 1,
        {'sent': len(sent), 'received': len(recv),
         'lastSend': sent[-1][2] if sent else None,
         'firstReceive': recv[0][2] if recv else None})
    props = (cap / 'driver-obs.txt').read_text()
    counters = {}
    for key in ('R24TxWaits', 'R24TxResumes', 'R24TxWakes', 'R24TxPending'):
        m = re.search(r'"' + key + r'" = (\d+)', props)
        counters[key] = int(m[1]) if m else -1
    add('r24-capacity-wait-and-automatic-resume',
        counters['R24TxWaits'] > 0 and
        counters['R24TxResumes'] > 0 and
        counters['R24TxWakes'] > 0 and counters['R24TxPending'] == 0,
        counters)
    overlap = next(c['detail'] for c in checks if c['id'] == 'multiple-mappings-live-at-once')
    add('r24-four-slot-bound', 1 < overlap.get('peakLive', 0) <= 4, overlap)
    result['scope'] = 'round24-four-slot-backpressure-continuous16'
    result['ok'] = all(c['state'] == 'ok' for c in checks)
    return result


if __name__ == '__main__':
    result = check(Path(sys.argv[1]))
    text = json.dumps(result, indent=2, default=str) + '\n'
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_bytes(text.encode('utf-8'))
    else:
        print(text)
    print('%d/%d checks passed' % (sum(c['state'] == 'ok' for c in result['checks']), len(result['checks'])))
    sys.exit(0 if result['ok'] else 1)
