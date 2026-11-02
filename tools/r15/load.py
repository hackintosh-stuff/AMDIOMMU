#!/usr/bin/env python3
"""Bounded round15 boot load: wait for fresh pool authorization, traverse RX ring,
then preserve the traditional four-request business batch. MTU/IP unchanged.
1200 echoed 1024-byte UDP payloads; separate flood token prevents suffix noise
from being mistaken for final business requests. No arbitrary-duration stress.
"""
import argparse
import importlib.util
import pathlib
import re
import select
import socket
import struct
import subprocess
import sys
import time

MAGIC = 0x31424F49

def now():
    return time.clock_gettime_ns(time.CLOCK_UPTIME_RAW)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('out')
    ap.add_argument('--iface', default='en2')
    ap.add_argument('--peer', default='192.168.50.122')
    ap.add_argument('--port', type=int, default=9110)
    a = ap.parse_args()
    out = pathlib.Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    token = int((out / 'token.txt').read_text().strip(), 0)
    batch = int((out / 'batch.txt').read_text().strip())
    if not 0 < token < 0x80000000 or batch != 4:
        raise ValueError('round15 requires nonzero low-half token and batch4')
    flood_token = token ^ 0x80000000
    with (out / 'load.txt').open('w') as load:
        def log(s):
            print(s, file=load, flush=True)
        log('load_iface : %s' % a.iface)
        log('load_peer : %s:%d' % (a.peer, a.port))
        log('load_run_token : 0x%08x' % token)
        log('load_requests : 4')
        log('load_flood_token : 0x%08x' % flood_token)
        log('load_flood_requests : 1200')
        log('load_payload_bytes : 1024')
        # Authorization is deliberately published only after the mapping and
        # invalidation commands. Avoid another fixed boot-time timing guess.
        deadline = time.monotonic() + 100
        local = None
        seeded = False
        while time.monotonic() < deadline:
            ip = subprocess.run(['ifconfig', a.iface], capture_output=True,
                                text=True).stdout
            m = re.search(r'\binet (\S+)', ip)
            if m and 'status: active' in ip:
                local = m.group(1)
                if not seeded:
                    route_seed = subprocess.run(['route', '-n', 'get', a.peer],
                        capture_output=True, text=True).stdout
                    if re.search(r'interface:\s*' + re.escape(a.iface) + r'\b', route_seed):
                        seed = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        seed.bind((local, 0))
                        seed.settimeout(0.15)
                        # A real pre-window observation prefix, NOT a parsed
                        # foreign business transaction. Run2 used req9999 with
                        # the flood token; its archived legacy rejection remains.
                        payload = bytes(1024)
                        seed.sendto(payload, (a.peer, a.port))
                        try:
                            echoed, _ = seed.recvfrom(8192)
                            log('load_seed_echo : %s at=%d' % (echoed == payload, now()))
                        except socket.timeout:
                            log('load_seed_echo : timeout')
                        seed.close()
                        seeded = True
                props = subprocess.run(['ioreg', '-l', '-w0', '-r', '-c',
                    'org_example_AMDMapperProbe'], capture_output=True,
                    text=True).stdout
                if '"m2-b2-r15-authorize" = "done"' in props:
                    match = re.search(r'"m2-b2-r15-inv-time" = "(0x[0-9a-fA-F]+)"', props)
                    if not match or now() - int(match.group(1), 0) > 400000000:
                        log('load_result FAIL-authorization-already-stale')
                        return 2
                    break
                if 'FAIL-r15-owned-pre-map' in props or '15e-abort' in props:
                    log('load_result FAIL-probe-refused')
                    return 2
            time.sleep(0.05)
        else:
            log('load_result FAIL-no-fresh-authorization')
            return 2
        route = subprocess.run(['route', '-n', 'get', a.peer],
                               capture_output=True, text=True).stdout
        rm = re.search(r'interface:\s*(\S+)', route)
        route_if = rm.group(1) if rm else 'unknown'
        log('load_route_interface : %s' % route_if)
        if route_if != a.iface:
            log('load_result FAIL-wrong-interface')
            return 2
        log('load_local : %s' % local)
        log('load_mach_at_start_ns: %d' % now())
        before = subprocess.run(['netstat', '-I', a.iface, '-b'],
                                capture_output=True, text=True).stdout
        (out / 'netstat-before.txt').write_text(before)
        time.sleep(0.08)  # give main window setup a bounded margin
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((local, 0))
        s.setblocking(False)
        received = set()
        bad = 0
        start = time.monotonic()
        log('load_flood_direction : windows-to-mac-no-echo')
        with (out / 'flood-client.log').open('w') as flood:
            def flog(line):
                print(line, file=flood, flush=True)
            flog('flood_bound %s:%d' % s.getsockname())
            flog('flood_token 0x%08x' % flood_token)
            # A single SMALL trigger asks Windows to inject1200 long frames.
            # No Mac echo/TX allocation is needed to turn the RX ring once.
            control = struct.pack('>III', MAGIC, flood_token, 9000) + bytes(20)
            s.sendto(control, (a.peer, a.port))
            flog('flood_control token=0x%08x req=9000 len=32 t_ns=%d' % (flood_token, now()))
            end_at = start + 1.9
            while time.monotonic() < end_at:
                ready, _, _ = select.select([s], [], [], 0.001)
                if ready:
                    while True:
                        try:
                            data, peer = s.recvfrom(8192)
                        except BlockingIOError:
                            break
                        if data == control and peer == (a.peer, a.port):
                            continue
                        if len(data) != 1024:
                            bad += 1
                            continue
                        magic, tok, req = struct.unpack_from('>III', data)
                        expected = struct.pack('>III', MAGIC, flood_token, req) + bytes(1012)
                        if (peer != (a.peer, a.port) or magic != MAGIC or
                                tok != flood_token or not 10001 <= req <= 11200 or data != expected):
                            bad += 1
                            continue
                        received.add(req)
                        flog('flood_recv token=0x%08x req=%d len=1024 payload_ok=1 from=%s:%d t_ns=%d' %
                             (tok, req, peer[0], peer[1], now()))
                if len(received) == 1200:
                    break
            flog('flood_summary expected=1200 received=%d bad=%d span_ns=%d' %
                 (len(received), bad, int((time.monotonic()-start)*1e9)))
        s.close()
        log('load_flood_summary : expected=1200 received=%d bad=%d' % (len(received), bad))
        # Keep the traditional four business echoes separate from long RX load.
        path = pathlib.Path(__file__).resolve().parents[1] / 'round11-client.py'
        spec = importlib.util.spec_from_file_location('round11client', str(path))
        client = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(client)
        client.PAD = bytes(20)
        sys.argv = [str(path), '--iface', a.iface, '--peer', a.peer,
            '--port', str(a.port), '--run-token', hex(token), '--requests', '4',
            '--interval-ms', '100', '--timeout-ms', '150',
            '--out', str(out / 'client.log')]
        rc = client.main()
        after = subprocess.run(['netstat', '-I', a.iface, '-b'],
                               capture_output=True, text=True).stdout
        (out / 'netstat-after.txt').write_text(after)
        log('load_mach_end_ns : %d' % now())
        log('load_done')
        return rc if rc else (0 if len(received) == 1200 and bad == 0 else 1)

if __name__ == '__main__':
    sys.exit(main())
