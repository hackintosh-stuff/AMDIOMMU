#!/usr/bin/env python3
"""R70 S3: read the capacity counters and generate pool-growing TCP traffic.

This tool does NOT decide acceptance. It exists so the S3 measurement boot can
answer one question the R69 analysis could not: how many concurrent Skywalk
segments (mapping records) and how many IOVA pages does a real 10 GbE client
hold. The counters it reads are published by the probe itself:

    r44-map-ok / r44-unmap-ok / r44-live-maps / r44-live-pages
    r44-peak-maps / r44-peak-pages        (peaks since the domain was prepared)
    r69-max-map-length / -pages / -runs   (largest request actually seen)
    r69-rejects-*                         (must stay zero for acceptance)
    r44-domain-profile* / r44-table-bytes / r69-admission

Traffic commands are deliberately dumb byte pipes: the point is to make the
client allocate packet-pool segments, not to verify payload integrity (the
R67/R67-2 tools own that). Both ends bind IPv6 addresses supplied on the
command line, so a flow can be pinned to one RTL8127 port.
"""
import argparse
import json
import socket
import subprocess
import sys
import time

PROBE_KEYS = (
    'r44-map-ok', 'r44-unmap-ok', 'r44-live-maps', 'r44-live-pages',
    'r44-peak-maps', 'r44-peak-pages', 'r44-map-rejected', 'r44-unmap-rejected',
    'r69-max-map-length', 'r69-max-map-pages', 'r69-max-map-runs',
    'r69-rejects-length', 'r69-rejects-options', 'r69-rejects-layout',
    'r69-rejects-records', 'r69-rejects-norange', 'r69-rejects-bits',
    'r44-domain-profile', 'r44-domain-profile-records', 'r44-domain-profile-pages',
    'r44-table-bytes', 'r44-profile', 'r44-profile-mode',
    'r52-domain-count', 'r44-target-faults', 'r44-state', 'r44-controller-ready',
)


def snapshot(args):
    values = {}
    text = subprocess.run(['ioreg', '-l', '-w0', '-r', '-c',
                           'org_example_AMDMapperProbe'],
                          capture_output=True, text=True).stdout
    for key in PROBE_KEYS:
        out = subprocess.run(['grep', '-oE', '"%s" = [^,}]+' % key],
                             input=text, capture_output=True, text=True).stdout
        seen = []
        for line in out.splitlines():
            token = line.split('=', 1)[1].strip().strip('"')
            if token not in seen:
                seen.append(token)
        if seen:
            values[key] = seen if len(seen) > 1 else seen[0]
    # Admission lives on the IOPCIDevice nodes, not on the probe.
    admitted = subprocess.run(['bash', '-c',
        "ioreg -l -w0 | grep -oE '\"r69-admission\"[^,}]+' | sort | uniq -c"],
        capture_output=True, text=True).stdout.strip()
    values['r69-admission'] = admitted.splitlines() if admitted else []
    record = {'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
              'boottime': subprocess.run(['sysctl', '-n', 'kern.boottime'],
                                         capture_output=True, text=True).stdout.strip(),
              'values': values}
    if args.out:
        open(args.out, 'w', encoding='utf-8').write(
            json.dumps(record, indent=2, sort_keys=True) + '\n')
    print(json.dumps(record, indent=2, sort_keys=True))
    if not text:
        print('FAIL: no probe instance', file=sys.stderr)
        return 1
    return 0


def _sock(family, addr, port):
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((addr, port))
    return sock


def server(args):
    sock = _sock(socket.AF_INET6, args.bind6, args.port)
    sock.listen(1)
    sock.settimeout(args.timeout)
    conn, peer = sock.accept()
    chunk = b'\xa5' * (1 << 20)
    sent = 0
    started = time.monotonic()
    try:
        while sent < args.bytes:
            n = min(len(chunk), args.bytes - sent)
            conn.sendall(chunk[:n])
            sent += n
    finally:
        conn.close()
        sock.close()
    record = {'role': 'server', 'peer': peer[0], 'bytes': sent,
              'seconds': round(time.monotonic() - started, 3)}
    _log(args, record)


def client(args):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.bind((args.bind6, 0))
    sock.settimeout(args.timeout)
    sock.connect((args.peer6, args.port))
    received = 0
    started = time.monotonic()
    while received < args.bytes:
        data = sock.recv(1 << 20)
        if not data:
            break
        received += len(data)
    sock.close()
    record = {'role': 'client', 'peer': args.peer6, 'bytes': received,
              'seconds': round(time.monotonic() - started, 3)}
    _log(args, record)


def _log(args, record):
    line = json.dumps(record, sort_keys=True)
    print(line)
    if args.log:
        with open(args.log, 'a', encoding='utf-8') as handle:
            handle.write(line + '\n')


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)

    snap = sub.add_parser('snapshot')
    snap.add_argument('--out')
    snap.set_defaults(func=snapshot)

    srv = sub.add_parser('server')
    srv.add_argument('--bind6', required=True)
    srv.add_argument('--port', type=int, required=True)
    srv.add_argument('--bytes', type=int, default=2 << 30)
    srv.add_argument('--timeout', type=float, default=60)
    srv.add_argument('--log')
    srv.set_defaults(func=server)

    cli = sub.add_parser('client')
    cli.add_argument('--bind6', required=True)
    cli.add_argument('--peer6', required=True)
    cli.add_argument('--port', type=int, required=True)
    cli.add_argument('--bytes', type=int, default=2 << 30)
    cli.add_argument('--timeout', type=float, default=60)
    cli.add_argument('--log')
    cli.set_defaults(func=client)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
