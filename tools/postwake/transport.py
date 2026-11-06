#!/usr/bin/env python3
"""Four persistent TCP6 streams; reuse the accepted deterministic byte verifier.

Each NIC gets an upload and a download socket. Every 8 MiB block is checked
byte-for-byte at the receiver and acknowledged with a SHA256 receipt. Neither
endpoint reconnects, retries a block, or writes payloads to disk.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
from pathlib import Path
import socket
import threading
import time

_spec = importlib.util.spec_from_file_location(
    '_r67_bytes', Path(__file__).resolve().parents[1] / 'dual/protocol.py')
P = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(P)
P.select_cycles(True)
BLOCK = 8 << 20
DIRECTIONS = ('upload', 'download')


def need(ok, message):
    if not ok:
        raise ValueError(message)


def journal(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    file = path.open('x', encoding='utf-8', newline='\n')
    lock = threading.Lock()

    def emit(row):
        with lock:
            print(json.dumps(row, sort_keys=True), file=file, flush=True)
    return file, emit


def client_stream(conn, role, direction, token, seconds, barrier, emit, binding):
    phase = role + '-before'
    endpoints = P.transport(conn)
    P.send_json(conn, dict(event='r67-start', role=role, direction=direction,
                           token=token, seconds=seconds, block_bytes=BLOCK))
    ready = P.receive_json(conn)
    need(ready.get('event') == 'r67-ready' and ready.get('role') == role and
         ready.get('direction') == direction and ready.get('token') == token,
         'peer did not accept this stream')
    P.validate_transport(ready, endpoints)
    barrier.wait(timeout=30)
    start = time.monotonic_ns()
    emit(dict(event='stream-start', role=role, direction=direction, token=token,
              start_ns=start, **binding, **endpoints))
    index = 0
    while time.monotonic_ns() - start < seconds * 1_000_000_000 or index == 0:
        payload_token = token + index
        P.send_json(conn, dict(event='block', index=index))
        began = time.monotonic_ns()
        result = P.stream(conn, payload_token, phase, direction, BLOCK,
                          sending=direction == 'upload')
        if direction == 'download':
            P.send_json(conn, dict(result, token=payload_token, phase=phase,
                                  direction=direction, **endpoints))
        receipt = P.receive_json(conn)
        P.validate_receipt(receipt, payload_token, phase, direction, BLOCK, result['sha256'])
        P.validate_transport(receipt, endpoints)
        need(receipt.get('index') == index, 'peer block sequence differs')
        emit(dict(result, event='block', role=role, direction=direction,
                  run_token=token, token=payload_token, index=index, start_ns=began,
                  end_ns=time.monotonic_ns(), peer_sha256=receipt['sha256'], **endpoints))
        index += 1
    P.send_json(conn, dict(event='done', blocks=index))
    done = P.receive_json(conn)
    need(done.get('event') == 'done' and done.get('blocks') == index,
         'peer final receipt is incomplete')
    emit(dict(event='stream-done', role=role, direction=direction, token=token,
              blocks=index, bytes=index * BLOCK, start_ns=start,
              end_ns=time.monotonic_ns(), **endpoints))


def peer_stream(conn, hello, token, role, budget, emit):
    direction = hello['direction']
    phase = role + '-before'
    seconds = hello.get('seconds', 0)
    need(0 < seconds <= budget - 60 and hello.get('block_bytes') == BLOCK,
         'invalid stream duration or block size')
    endpoints = P.transport(conn)
    P.send_json(conn, dict(event='r67-ready', token=token, role=role,
                           direction=direction, **endpoints))
    index, deadline = 0, time.monotonic() + budget
    emit(dict(event='stream-start', role=role, direction=direction, token=token, **endpoints))
    while True:
        need(time.monotonic() < deadline, 'finite peer deadline exceeded')
        request = P.receive_json(conn)
        if request.get('event') == 'done':
            need(request.get('blocks') == index and index > 0, 'invalid final block count')
            P.send_json(conn, dict(event='done', blocks=index))
            emit(dict(event='stream-done', role=role, direction=direction,
                      token=token, blocks=index, bytes=index * BLOCK, **endpoints))
            return
        need(request == {'event': 'block', 'index': index}, 'unexpected block sequence')
        payload_token = token + index
        result = P.stream(conn, payload_token, phase, direction, BLOCK,
                          sending=direction == 'download')
        if direction == 'download':
            receipt = P.receive_json(conn)
            P.validate_receipt(receipt, payload_token, phase, direction, BLOCK, result['sha256'])
            P.validate_transport(receipt, endpoints)
        record = dict(result, event='block', role=role, direction=direction, index=index,
                      token=payload_token, run_token=token, phase=phase, **endpoints)
        P.send_json(conn, record)
        emit(record)
        index += 1


def serve(listener, token, role, budget, emit):
    """Exactly two directional connections for one NIC, then exit."""
    sessions, futures, seen = [], [], set()
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            for _ in DIRECTIONS:
                listener.settimeout(60)
                conn, _ = listener.accept()
                sessions.append(conn)
                conn.settimeout(60)
                hello = P.receive_json(conn)
                direction = hello.get('direction')
                need(hello.get('event') == 'r67-start' and hello.get('token') == token
                     and hello.get('role') == role and direction in DIRECTIONS
                     and direction not in seen, 'unexpected stream identity')
                seen.add(direction)
                futures.append(pool.submit(peer_stream, conn, hello, token, role, budget, emit))
            for future in futures:
                future.result()
        emit(dict(event='result', ok=True, role=role, token=token, streams=2))
    finally:
        for conn in sessions:
            conn.close()


def peer_main(default_token):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role', choices=('a', 'b'), required=True)
    parser.add_argument('--bind6', required=True)
    parser.add_argument('--port', required=True, type=int)
    parser.add_argument('--token', type=lambda x: int(x, 0), default=default_token)
    parser.add_argument('--budget', type=int, default=900)
    parser.add_argument('--log', type=Path, required=True)
    args = parser.parse_args()
    need(360 <= args.budget <= 1800 and 0 < args.port <= 65535, 'invalid finite budget/port')
    need(0 < args.token < 0x7f000000, 'invalid token')
    file, emit = journal(args.log)
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            listener.bind(P.sockaddr(args.bind6, args.port))
            listener.listen(2)
            emit(dict(event='listening', role=args.role, token=args.token))
            serve(listener, args.token, args.role, args.budget, emit)
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        emit(dict(event='result', ok=False, role=args.role, error=str(exc)))
        return 1
    finally:
        file.close()
