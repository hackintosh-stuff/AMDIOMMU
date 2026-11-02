#!/usr/bin/env python3
"""Finite exclusive UDP echo + paced, one-way long RX stimulus for round15.
A 32-byte req9000 trigger binds destination to its actual source tuple; send
exactly1200 1024-byte datagrams (req10001..11200), once per token. No ICMP,
raw socket, network configuration, or infinite traffic loop is used.
"""
import argparse
import select
import socket
import struct
import time

MAGIC = 0x31424f49
ap = argparse.ArgumentParser()
ap.add_argument('--log', required=True)
ap.add_argument('--bind', default='192.168.50.122')
ap.add_argument('--port', type=int, default=9110)
ap.add_argument('--seconds', type=float, default=900)
a = ap.parse_args()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
    s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
s.bind((a.bind, a.port))
with open(a.log, 'w', encoding='utf-8', newline='\n') as f:
    def emit(line):
        print(line, file=f, flush=True)
    emit('peer_start bind=%s:%d at=%d' % (a.bind, a.port, time.monotonic_ns()))
    end = time.monotonic() + a.seconds
    seen_tokens = set()
    flood = None
    count = 0
    while time.monotonic() < end:
        now = time.monotonic()
        if flood:
            while flood['req'] <= 11200 and now >= flood['due']:
                req, token, target = flood['req'], flood['token'], flood['target']
                data = struct.pack('>III', MAGIC, token, req) + bytes(1012)
                n = s.sendto(data, target)
                if n != len(data):
                    raise RuntimeError('short UDP send')
                emit('peer_sent token=0x%08x req=%d len=%d to=%s:%d t=%d' %
                     (token, req, n, target[0], target[1], time.monotonic_ns()))
                flood['req'] += 1
                flood['due'] += .001
                now = time.monotonic()
            if flood['req'] > 11200:
                emit('peer_flood_done token=0x%08x sent=1200 at=%d' %
                     (flood['token'], time.monotonic_ns()))
                flood = None
        timeout = min(.2, max(0, end-time.monotonic()))
        if flood:
            timeout = min(timeout, max(0, flood['due']-time.monotonic()))
        if not select.select([s], [], [], timeout)[0]:
            continue
        try:
            data, addr = s.recvfrom(8192)
        except ConnectionResetError:
            continue
        if len(data) < 12:
            continue
        magic, token, req = struct.unpack_from('>III', data)
        emit('peer_recv token=0x%08x req=%d len=%d from=%s:%d t=%d' %
            (token, req, len(data), addr[0], addr[1], time.monotonic_ns()))
        emit('RECV %d bytes from %s:%d head=%s' % (len(data), addr[0], addr[1], data[:12].hex()))
        n = s.sendto(data, addr)
        emit('peer_sent token=0x%08x req=%d len=%d to=%s:%d t=%d' %
            (token, req, n, addr[0], addr[1], time.monotonic_ns()))
        count += 1
        if magic == MAGIC and req == 9000 and len(data) == 32 and token not in seen_tokens:
            seen_tokens.add(token)
            if flood:
                raise RuntimeError('concurrent finite triggers refused')
            flood = {'req': 10001, 'token': token, 'target': addr,
                     'due': time.monotonic() + .02}
            emit('peer_flood_start token=0x%08x to=%s:%d count=1200 payload=1024' %
                 (token, addr[0], addr[1]))
    emit('peer_stop echoed=%d at=%d' % (count, time.monotonic_ns()))
s.close()
