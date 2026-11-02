#!/usr/bin/env python3
"""Round-10: decode the v2 snapshot and show which TX records parsed.

Run against the hex dumped from the driver's rtl812x-obs-snapshot property.
Prints every TX-submit record with its business fields so it is visible WHY a
record did or did not parse.
"""
import struct
import sys

HDR = 104
REC = 72

KIND = {0: 'none', 1: 'tx-submit', 2: 'tx-done', 3: 'rx-done', 4: 'tx-doorbell'}
PKT = {0: 'parsed', 1: 'no-magic', 2: 'not-ipv4', 3: 'vlan', 4: 'fragmented',
       5: 'ip-options', 6: 'not-udp', 7: 'short', 8: 'truncated',
       9: 'not-tx', 10: 'tcp'}


def pktname(fl):
    if fl & 1:
        return 'PARSED'
    out = []
    for bit, name in PKT.items():
        if bit and (fl >> bit) & 1:
            out.append(name)
    return ','.join(out) if out else 'none'


def main():
    path = sys.argv[1]
    hexs = open(path).read().strip()
    blob = bytes.fromhex(hexs)
    print('blob %d bytes' % len(blob))
    if len(blob) < HDR:
        raise SystemExit('too short')
    f = struct.unpack('<20I', blob[:80])
    names = ['magic', 'version', 'recSize', 'capacity', 'head', 'wrapped',
             'dropped', 'pubId', 'firstTicket', 'lastTicket', 'validCount',
             'lostCount', 'epoch', 'busDevFn', 'vendorId', 'deviceId',
             'ifUnit', 'macHi', 'macLo', 'flags']
    for n, v in zip(names, f):
        print('  %-12s 0x%-10x %d' % (n, v, v))
    print('  tStart      %d' % struct.unpack('<Q', blob[80:88])[0])
    print('  tPublished  %d' % struct.unpack('<Q', blob[88:96])[0])

    n = (len(blob) - HDR) // REC
    print('\n%d records' % n)
    first = f[8]
    counts = {}
    tx = []
    for i in range(n):
        off = HDR + i * REC
        (t, addr, seq, kind, cum, slot, gen, batch,
         o1, o2, ln, fl, tok, req, flow, pf) = struct.unpack_from(
            '<QQIIIIIIIIIIIIII', blob, off)
        counts[kind] = counts.get(kind, 0) + 1
        if kind == 1:
            tx.append((i, t, cum, slot, addr, ln, fl, tok, req, pf))
    print('kinds: %s' % {KIND.get(k, k): v for k, v in counts.items()})
    print('\nTX submits: %d' % len(tx))
    for (i, t, cum, slot, addr, ln, fl, tok, req, pf) in tx:
        print('  idx=%-4d t=%-12d cum=0x%03x slot=0x%03x addr=0x%-11x '
              'len=%3d flags=0x%x pkt=0x%03x(%s) token=0x%08x req=%d'
              % (i, t, cum, slot, addr, ln, fl, pf, pktname(pf), tok, req))


if __name__ == '__main__':
    main()
