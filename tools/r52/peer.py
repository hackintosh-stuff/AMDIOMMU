#!/usr/bin/env python3
"""Serve one selected R52 role's finite IPv6 transfers, then exit."""
import argparse
import json
import socket
import time
from common import protocol as P, project_path


def serve(listener, token, seconds, mode, role, emit):
    deadline = time.monotonic() + seconds
    transfers = P.transfers(mode, role)
    for phase, direction, size in transfers:
        listener.settimeout(max(.001, deadline - time.monotonic()))
        conn, _ = listener.accept()
        with conn:
            conn.settimeout(min(60, max(.001, deadline - time.monotonic())))
            started = time.monotonic_ns()
            endpoints = P.transport(conn)
            if P.parse_request(P.receive(conn, P.HEADER.size)) != (token, phase, direction, size):
                raise RuntimeError('unexpected transfer role/order/token')
            P.send_json(conn, dict(endpoints, event='ready', token=token,
                                   phase=phase, direction=direction))
            result = P.stream(conn, token, phase, direction, size, sending=direction == 'download')
            if direction == 'download':
                receipt = P.receive_json(conn)
                P.validate_receipt(receipt, token, phase, direction, size, result['sha256'])
                P.validate_transport(receipt, endpoints)
            record = dict(P.transfer_record('peer', token, phase, direction, result, started), **endpoints)
            P.send_json(conn, record)
            emit(record)
    emit({'event': 'result', 'side': 'peer', 'ok': True, 'role': role,
          'transfers': len(transfers), 'family': 'IPv6'})


def main(default_token=0x52c0de52):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-token', type=lambda value: int(value, 0), default=default_token)
    parser.add_argument('--mode', choices=('auto', 'off'), default='auto')
    parser.add_argument('--role', choices=('a', 'b'), required=True, help='a=down target; b=other device')
    parser.add_argument('--bind6', required=True, help='numeric peer IPv6 with this host scope if link-local')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--seconds', type=int, default=600)
    parser.add_argument('--log', required=True)
    args = parser.parse_args()
    P.request(args.run_token, *P.transfers(args.mode, args.role)[0])
    if not 0 < args.seconds <= 1800 or not 0 < args.port <= 65535:
        raise ValueError('invalid finite peer budget or port')
    address, path = P.sockaddr(args.bind6, args.port), project_path(args.log)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8', newline='\n') as log:
        emit = lambda value: print(json.dumps(value, sort_keys=True), file=log, flush=True)
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                sock.bind(address)
                sock.listen(1)
                emit({'event': 'start', 'side': 'peer', 'role': args.role, 'mode': args.mode,
                      'token': args.run_token, 'family': 'IPv6', 'local': P.endpoint(sock.getsockname())})
                serve(sock, args.run_token, args.seconds, args.mode, args.role, emit)
        except (OSError, ValueError, RuntimeError) as exc:
            emit({'event': 'result', 'side': 'peer', 'ok': False, 'error': str(exc)})
            return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
