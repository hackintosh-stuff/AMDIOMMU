#!/usr/bin/env python3
"""Round20 application bytes for one declared 16-request serial batch.

Same three length classes as round 19, but the layout is INTERLEAVED so the
multi-mbuf path is exercised immediately rather than after twelve small frames:

  * 32 B   payload (74 B frame)  -- small-frame regression, one mbuf;
  * 120 B  payload (162 B frame) -- small enough for one mbuf, with in-page
    offsets that can cross a page;
  * 1472 B payload (1514 B frame) -- the largest legal UDP payload for this
    MTU; on this stack it is handed to the driver as a two-mbuf chain, so the
    round-20 driver describes it with withAddressRanges and the command can
    answer with several DMA runs.

The first large frame is request 2 (one small frame before it), and requests
2, 4, 6, 8 and 11 are large: five real multi-mbuf frames in one 16-request
batch. Nothing here requires jumbo frames, VLAN tags or another subnet.
"""
import hashlib
import struct

MAGIC = 0x31424F49  # 'IOB1': same business magic the driver's obsParseBiz looks for
REQUESTS = tuple(range(1, 17))
SEED = bytes(1024)  # r15's nonmagic pre-window observation prefix, unchanged
LARGE = (2, 4, 6, 8, 11)


def length_of(req):
    """Deterministic payload size per request (see the module docstring)."""
    if req not in REQUESTS:
        raise ValueError('round20 requires req 1..16')
    if req in LARGE:
        return 1472
    if req in (3, 7, 10, 13, 15):
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
        raise ValueError('round20 requires a low-half nonzero token')
    size = length_of(req)
    header = struct.pack('>III', MAGIC, token, req)
    body = _stream(b'round20-std-tx-v1\x00' + header, size - len(header))
    return header + body


def identify(data):
    if len(data) < 12:
        return None
    magic, token, req = struct.unpack_from('>III', data)
    return (token, req) if magic == MAGIC else None


def evidence(data):
    return 'len=%d sha256=%s payload=%s' % (
        len(data), hashlib.sha256(data).hexdigest(), data.hex())


def lengths():
    return {req: length_of(req) for req in REQUESTS}
