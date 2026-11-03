#!/usr/bin/env python3
"""Serve four finite TCP streams; exit after both phases have completed."""
import argparse
import json
import socket
import time
from common import protocol as P, project_path


def serve(listener, token, seconds, emit):
    deadline = time.monotonic() + seconds
    for phase, direction, size in P.TRANSFERS:
        listener.settimeout(max(.001, deadline - time.monotonic()))
        conn, address = listener.accept()
        with conn:
            conn.settimeout(min(60, max(.001, deadline - time.monotonic())))
            started = time.monotonic_ns()
            got = P.parse_request(P.receive(conn, P.HEADER.size))
            if got != (token, phase, direction, size):
                raise RuntimeError('unexpected transfer order or token')
            P.send_json(conn, {'event': 'ready', 'token': token, 'phase': phase, 'direction': direction})
            result = P.stream(conn, token, phase, direction, size, sending=direction == 'download')
            if direction == 'download':
                receipt = P.receive_json(conn)
                P.validate_receipt(receipt, token, phase, direction, size, result['sha256'])
            record = P.transfer_record('peer', token, phase, direction, result, started)
            P.send_json(conn, record)
            emit(dict(record, address=address[0]))
    emit({'event': 'result', 'side': 'peer', 'ok': True, 'transfers': 4})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-token', type=lambda x: int(x, 0), default=0x45c0de45)
    parser.add_argument('--bind', default='192.168.50.122')
    parser.add_argument('--port', type=int, default=9111)
    parser.add_argument('--seconds', type=int, default=600)
    parser.add_argument('--log', default='runs/r45/peer.log')
    args = parser.parse_args()
    P.request(args.run_token, *P.TRANSFERS[0])
    if not 0 < args.seconds <= 1800 or not 0 < args.port <= 65535:
        raise ValueError('invalid finite peer budget or port')
    path = project_path(args.log)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8', newline='\n') as log:
        emit = lambda value: print(json.dumps(value, sort_keys=True), file=log, flush=True)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                sock.bind((args.bind, args.port))
                sock.listen(1)
                emit({'event': 'start', 'side': 'peer', 'token': args.run_token,
                      'bind': args.bind, 'port': args.port})
                serve(sock, args.run_token, args.seconds, emit)
        except (OSError, ValueError, RuntimeError) as exc:
            emit({'event': 'result', 'side': 'peer', 'ok': False, 'error': str(exc)})
            return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
