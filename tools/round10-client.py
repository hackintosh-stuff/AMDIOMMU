#!/usr/bin/env python3
"""round10-client.py -- the client for round 10's controlled batch.

WHAT THIS PROVES, AND WHAT IT DOES NOT
--------------------------------------
It proves, on the client side:
  * which local address and port the datagram was bound to and sent from;
  * which route the kernel chose, and therefore which interface carried it;
  * the exact run token and request id in each payload;
  * the peer's echo came back and matched byte for byte.

It does NOT prove the datagram left through a particular PCI function. That is
what the driver's own TX records do, joined by (token, reqId). The two sides
are deliberately independent: the client says "I sent token T request N from
address A", the driver says "I submitted a datagram carrying token T request N
from descriptor index K to address P at time t". Neither can manufacture the
other.

THE INTERFACE IS NOT ASSUMED
----------------------------
`--iface` is checked, not trusted: the script looks up that interface's IPv4
address, asks the kernel for the route to the peer, and REFUSES to run if the
route does not leave through the requested interface. Round 9 bound a source
address on en0 and called the result "the controlled chain", without ever
checking that en0 was the device under test -- it was not.
"""
import argparse
import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
import time

MAGIC = 0x31424F49   # 'IOB1'
PAD = b'.' * 20      # fixed padding so the payload length is stable


def sh(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def iface_ipv4(iface):
    rc, out, _ = sh('/sbin/ifconfig %s' % iface)
    if rc != 0:
        return None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith('inet '):
            return line.split()[1]
    return None


def route_for(dst_ip):
    rc, out, _ = sh('/sbin/route -n get %s' % dst_ip)
    info = {}
    if rc != 0:
        return info
    for line in out.splitlines():
        if ':' in line:
            k, v = line.split(':', 1)
            info[k.strip()] = v.strip()
    return info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--iface', required=True,
                    help='the BSD interface that must carry the traffic')
    ap.add_argument('--peer', required=True, help='peer IP')
    ap.add_argument('--port', type=int, default=9110)
    ap.add_argument('--run-token', type=int, required=True)
    ap.add_argument('--requests', type=int, default=4)
    ap.add_argument('--interval-ms', type=int, default=250)
    ap.add_argument('--timeout-ms', type=int, default=1000)
    ap.add_argument('--out', required=True)
    a = ap.parse_args()

    out = open(a.out, 'w', encoding='utf-8', newline='\n')
    def log(s):
        out.write(s + '\n')
        out.flush()

    log('client_start_ns %d' % time.monotonic_ns())
    log('client_iface %s' % a.iface)
    log('client_peer %s:%d' % (a.peer, a.port))
    log('client_run_token 0x%08x' % a.run_token)
    log('client_requests %d' % a.requests)

    local = iface_ipv4(a.iface)
    if not local:
        log('client_result FAIL-no-ipv4-on-%s' % a.iface)
        out.close()
        return 1
    log('client_local %s' % local)

    # ---- refuse to run if the route does not leave through --iface ----
    #
    # This is the check round 9 did not have. Without it, a source-address
    # bind on en0 looks exactly like a successful "controlled transfer" even
    # though the observed device was en2.
    r = route_for(a.peer)
    log('client_route_interface %s' % r.get('interface', 'unknown'))
    log('client_route_gateway %s' % r.get('gateway', 'none'))
    log('client_route_src %s' % r.get('local address', 'none'))
    if r.get('interface') != a.iface:
        log('client_result FAIL-route-leaves-through-%s-not-%s'
            % (r.get('interface', 'unknown'), a.iface))
        out.close()
        return 1

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(a.timeout_ms / 1000.0)
    try:
        s.bind((local, 0))
    except OSError as e:
        log('client_result FAIL-bind-%s' % e)
        out.close()
        return 1
    bound = s.getsockname()
    log('client_bound %s:%d' % (bound[0], bound[1]))

    sent = 0
    acked = 0
    bad = 0
    t0 = time.monotonic_ns()

    for req in range(1, a.requests + 1):
        payload = struct.pack('>III', MAGIC, a.run_token, req) + PAD
        tsend = time.monotonic_ns()
        try:
            s.sendto(payload, (a.peer, a.port))
        except OSError as e:
            bad += 1
            log('client_send_fail req=%d %s' % (req, e))
            continue
        sent += 1
        log('client_sent token=0x%08x req=%d len=%d t_ns=%d'
            % (a.run_token, req, len(payload), tsend))

        try:
            data, addr = s.recvfrom(4096)
        except socket.timeout:
            log('client_timeout token=0x%08x req=%d' % (a.run_token, req))
            bad += 1
            continue
        trecv = time.monotonic_ns()
        if data != payload:
            bad += 1
            log('client_echo_mismatch token=0x%08x req=%d got=%d want=%d'
                % (a.run_token, req, len(data), len(payload)))
            continue
        magic, tok, rq = struct.unpack('>III', data[:12])
        if magic != MAGIC or tok != a.run_token or rq != req:
            bad += 1
            log('client_echo_wrong_id token=0x%08x req=%d got_token=0x%08x '
                'got_req=%d' % (a.run_token, req, tok, rq))
            continue
        acked += 1
        log('client_recv token=0x%08x req=%d t_ns=%d rtt_ns=%d'
            % (a.run_token, req, trecv, trecv - tsend))

        if req < a.requests:
            time.sleep(a.interval_ms / 1000.0)

    t1 = time.monotonic_ns()
    log('client_summary sent=%d acked=%d bad=%d span_ns=%d'
        % (sent, acked, bad, t1 - t0))
    ok = (sent == a.requests and acked == a.requests and bad == 0)
    log('client_result %s' % ('OK' if ok else 'PROBLEM'))
    log('client_end_ns %d' % time.monotonic_ns())
    out.close()
    s.close()
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
