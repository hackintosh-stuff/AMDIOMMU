#!/usr/bin/env python3
"""Round26 ordinary UDP application payloads; no kernel business selection.

The token and request id belong only to the client/peer integrity check.  The
driver's obsParseBiz reads a different four-byte magic at the UDP payload start,
so neither these requests nor the ordinary probes authorize a DMA mapping.
"""
import hashlib
import struct

MAGIC = b'R26P'
REQUESTS = tuple(range(1, 513))
SEED = bytes(1024)
LARGE = (2, 4, 6, 8, 11)
BURST = 16


def bursts():
    """32 consecutive groups; send every member before receiving any echo."""
    return [REQUESTS[i:i + BURST] for i in range(0, len(REQUESTS), BURST)]


def length_of(req):
    if req not in REQUESTS:
        raise ValueError('round26 requires req 1..512')
    pattern_req = (req - 1) % BURST + 1
    if pattern_req in LARGE:
        return 1472
    if pattern_req in (3, 7, 10, 13, 15):
        return 120
    return 32


def _stream(seed, size):
    out = bytearray()
    block = seed
    while len(out) < size:
        block = hashlib.sha256(block).digest()
        out += block
    return bytes(out[:size])


def payload(token, req):
    if not 0 < token < 0x80000000:
        raise ValueError('round26 requires a low-half nonzero userspace token')
    size = length_of(req)
    header = struct.pack('>4sII', MAGIC, token, req)
    body = _stream(b'round26-ordinary-load-v1\x00' + header, size - len(header))
    return header + body


def identify(data):
    if len(data) < 12:
        return None
    magic, token, req = struct.unpack_from('>4sII', data)
    return (token, req) if magic == MAGIC else None


def evidence(data):
    return 'len=%d sha256=%s payload=%s' % (
        len(data), hashlib.sha256(data).hexdigest(), data.hex())


def lengths():
    return {req: length_of(req) for req in REQUESTS}


# Preserve the r21 pre/window/after-exit probe format for collection tools.
ORD_MAGIC = 0x3144524F
ORD_SIZE = 200


def ordinary(seq):
    if not 0 < seq < 1 << 32:
        raise ValueError('ordinary seq out of range')
    head = struct.pack('>III', ORD_MAGIC, seq, 0)
    body = _stream(b'round22-ordinary-v1\x00' + head, ORD_SIZE - len(head))
    return head + body


def ordinary_seq(data):
    if len(data) < 12:
        return None
    magic, seq, _ = struct.unpack_from('>III', data)
    return seq if magic == ORD_MAGIC and seq else None
