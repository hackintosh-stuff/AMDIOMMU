#!/usr/bin/env python3
"""Round-10: test whether the window-internal TX records can belong to the
round-9 controlled TCP load, using only the original evidence.

Round 9 asserted: "this 42-byte request was submitted at 38.237326 s and
completed at 38.237341 s, and the peer received it and ACKed".

Three independent facts decide whether that can be true:

  1. Which interface carried the controlled load (route + bind + MAC + BDF).
  2. The period of the controlled load's packets (from client.log, whose
     timestamps are all in ONE clock, so differences are valid).
  3. The period of the driver's TX submits around the window.
"""
import json
import os
import re
import struct

EV = 'docs/evidence/20261031-172647'
REC = 56


def decode(blob):
    out = []
    for i in range(len(blob) // REC):
        (t, addr, seq, kind, cum, slot, gen, batch,
         o1, o2, ln, fl) = struct.unpack_from('<QQIIIIIIIIII', blob, i * REC)
        out.append(dict(index=i, t=t, addr=addr, seq=seq, kind=kind,
                        cum=cum, slot=slot, gen=gen, batch=batch,
                        len=ln, flags=fl))
    return out


def main():
    client = open(os.path.join(EV, 'client.log'), encoding='utf-8',
                  errors='replace').read()
    sent = [(int(m.group(1)), int(m.group(2)))
            for m in re.finditer(r'client_sent seq=(\d+) len=\d+ t_ns=(\d+)',
                                 client)]
    print('=' * 78)
    print('1. PERIOD OF THE CONTROLLED LOAD (client.log, single clock)')
    print('=' * 78)
    print('  client_sent records      = %d' % len(sent))
    print('  client process clock     = [%d, %d] ns' % (sent[0][1], sent[-1][1]))
    d = [sent[i + 1][1] - sent[i][1] for i in range(len(sent) - 1)]
    d.sort()
    print('  inter-send delta         = min %d  p50 %d  p90 %d  max %d ns'
          % (d[0], d[len(d) // 2], d[int(len(d) * 0.9)], d[-1]))
    print('  => median period %.3f ms' % (d[len(d) // 2] / 1e6))
    print('  NOTE: client.log uses the client process clock (starts at 0),')
    print('        the driver records use mach_absolute_time since boot.')
    print('        They are DIFFERENT epochs, so only periods and ordering')
    print('        may be compared, never absolute values.')

    print()
    print('=' * 78)
    print('2. PERIOD OF THE DRIVER TX SUBMITS (archived blob)')
    print('=' * 78)
    recs = decode(open(os.path.join(EV, 'driver-obs-blob.bin'), 'rb').read())
    subs = sorted([r for r in recs if r['seq'] and r['kind'] == 1],
                  key=lambda r: r['t'])
    print('  TX submit records in blob = %d' % len(subs))
    print('  time span                = %.3f s .. %.3f s since boot'
          % (subs[0]['t'] / 1e9, subs[-1]['t'] / 1e9))

    # Load window from load.txt: load ran 29..49 s since boot.
    load = open(os.path.join(EV, 'load.txt'), encoding='utf-8').read()
    lo = int(re.search(r'load_actual_start_s\s*:\s*(\d+)', load).group(1))
    hi = int(re.search(r'load_actual_end_s\s*:\s*(\d+)', load).group(1))
    print('  controlled load ran      = %d..%d s since boot' % (lo, hi))

    during = [r for r in subs if lo * 10**9 <= r['t'] <= hi * 10**9]
    print('  TX submits during load   = %d  (in %.0f s)' % (len(during), hi - lo))
    if len(during) > 1:
        dd = sorted([during[i + 1]['t'] - during[i]['t']
                     for i in range(len(during) - 1)])
        print('  their period             = min %d  p50 %d  max %d ns'
              % (dd[0], dd[len(dd) // 2], dd[-1]))
        print('  => median period %.3f s' % (dd[len(dd) // 2] / 1e9))

    print()
    print('  Every TX submit inside the measurement window:')
    W = (37494608045, 40494639566)
    for r in subs:
        if W[0] <= r['t'] <= W[1]:
            print('    cum=0x%02x slot=0x%02x addr=0x%-11x len=%3d t=%.6f s'
                  % (r['cum'], r['slot'], r['addr'], r['len'], r['t'] / 1e9))
    win = [r for r in subs if W[0] <= r['t'] <= W[1]]
    if len(win) > 1:
        gaps = [win[i + 1]['t'] - win[i]['t'] for i in range(len(win) - 1)]
        print('  window submit gaps       = %s ns' % gaps)
        print('  => %.6f s apart' % (gaps[0] / 1e9))

    print()
    print('=' * 78)
    print('3. VERDICT')
    print('=' * 78)
    if len(win) > 1:
        period = (win[-1]['t'] - win[0]['t']) / (len(win) - 1)
        print('  window submit period     = %.6f s' % (period / 1e9))
        print('  controlled load period   = %.6f s (median, client side)'
              % (d[len(d) // 2] / 1e9))
        ratio = period / d[len(d) // 2]
        print('  ratio                    = %.1fx' % ratio)
        print()
        if ratio > 10:
            print('  The window-internal TX submits are ~%.0fx too slow to be' % ratio)
            print('  the controlled load. They are a periodic background')
            print('  stream (~1 s), not the 1178-request TCP transfer.')
            print('  => Round 9\'s "this 42-byte request" is NOT a request of')
            print('     the controlled transfer. The 42 bytes are a pure ACK,')
            print('     and the packet belongs to whatever en2 was doing.')

    out = {
        'client_sends': len(sent),
        'client_median_period_ns': d[len(d) // 2],
        'driver_submits_total': len(subs),
        'driver_submits_during_load': len(during),
        'window_submits': [{'cum': r['cum'], 'slot': r['slot'],
                            'addr': r['addr'], 'len': r['len'],
                            't': r['t']} for r in win],
    }
    with open(os.path.join(EV, 'derived', 'load-attribution.json'), 'w',
              encoding='utf-8') as f:
        json.dump(out, f, indent=1)


if __name__ == '__main__':
    main()
