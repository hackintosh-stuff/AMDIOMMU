#!/usr/bin/env python3
"""Finite ordinary TCP streams with deterministic, position-sensitive bytes."""
import hashlib
import json
import struct
import time

MAGIC = b'R45TCP1\0'
HEADER = struct.Struct('!8sIIII')
CHUNK = 65536
TRANSFERS = (('before', 'upload', 128 << 20), ('before', 'download', 128 << 20),
             ('after', 'upload', 8 << 20), ('after', 'download', 8 << 20))
PHASE_CODES, DIRECTION_CODES = ('before', 'after'), ('upload', 'download')


def request(token, phase, direction, size):
    if not 0 < token < 0x80000000 or (phase, direction, size) not in TRANSFERS:
        raise ValueError('invalid finite TCP transfer')
    return HEADER.pack(MAGIC, token, PHASE_CODES.index(phase), DIRECTION_CODES.index(direction), size)


def parse_request(data):
    magic, token, phase, direction, size = HEADER.unpack(data)
    if magic != MAGIC or phase >= len(PHASE_CODES) or direction >= len(DIRECTION_CODES):
        raise ValueError('invalid TCP header')
    value = (token, PHASE_CODES[phase], DIRECTION_CODES[direction], size)
    request(*value)
    return value


def chunks(token, phase, direction, size):
    seed = request(token, phase, direction, size)
    for index, offset in enumerate(range(0, size, CHUNK)):
        yield hashlib.shake_256(seed + struct.pack('!I', index)).digest(min(CHUNK, size - offset))


def expected_digest(token, phase, direction, size):
    digest = hashlib.sha256()
    for data in chunks(token, phase, direction, size):
        digest.update(data)
    return digest.hexdigest()


def receive(sock, size):
    value = bytearray()
    while len(value) < size:
        part = sock.recv(size - len(value))
        if not part:
            raise RuntimeError('TCP connection ended before the declared bytes')
        value.extend(part)
    return bytes(value)


def send_json(sock, value):
    data = json.dumps(value, separators=(',', ':')).encode('utf-8')
    if len(data) > 4096:
        raise ValueError('TCP receipt too large')
    sock.sendall(struct.pack('!I', len(data)) + data)


def receive_json(sock):
    size = struct.unpack('!I', receive(sock, 4))[0]
    if not 0 < size <= 4096:
        raise ValueError('invalid TCP receipt size')
    return json.loads(receive(sock, size))


def stream(sock, token, phase, direction, size, sending):
    actual, expected = hashlib.sha256(), hashlib.sha256()
    count = 0
    for pattern in chunks(token, phase, direction, size):
        expected.update(pattern)
        if sending:
            sock.sendall(pattern)
            data = pattern
        else:
            data = receive(sock, len(pattern))
            if data != pattern:
                raise RuntimeError('TCP payload differs at offset %d' % count)
        actual.update(data)
        count += len(data)
    return {'bytes': count, 'sha256': actual.hexdigest(),
            'expected_sha256': expected.hexdigest(), 'verified': True}


def validate_receipt(value, token, phase, direction, size, digest):
    if (value.get('token'), value.get('phase'), value.get('direction'), value.get('bytes'),
        value.get('sha256'), value.get('expected_sha256'), value.get('verified')) != (
            token, phase, direction, size, digest, digest, True):
        raise RuntimeError('peer TCP receipt differs from this transfer')


def transfer_record(side, token, phase, direction, result, started):
    duration = time.monotonic_ns() - started
    return dict(result, event='transfer', side=side, token=token, phase=phase,
                direction=direction, duration_ns=duration,
                mib_per_second=result['bytes'] / (1 << 20) * 1e9 / max(1, duration))
