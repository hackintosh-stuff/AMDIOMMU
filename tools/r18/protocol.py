#!/usr/bin/env python3
"""Round17 application bytes for one declared 32-request serial batch.

Three length classes, chosen for a reason and kept deterministic:
  * 32 B   payload (74 B frame)  -- the round-16 baseline shape: a small frame
    that fits in a plain mbuf, so its physical offset is whatever the mbuf
    allocator hands out.
  * 120 B  payload (162 B frame) -- still small enough for a plain mbuf, but
    long enough that the high in-page offsets cross into the next page. This
    is the class that can produce a real cross-page TX segment without
    changing the MTU.
  * 1472 B payload (1514 B frame) -- the largest legal UDP payload for a
    1500-byte MTU, i.e. the widest single frame the ring can carry here.
No class requires jumbo frames, VLAN tags, or a different subnet.
"""
import hashlib
import struct

MAGIC = 0x31424F49  # 'IOB1': same business magic the driver's obsParseBiz looks for
REQUESTS = tuple(range(1, 17))
SEED = bytes(1024)  # r15's nonmagic pre-window observation prefix, unchanged


def length_of(req):
    """Two classes of frame, ordered on purpose.

    Requests 1..12 use payload sizes that still live in ONE mbuf (74 / 162 B
    frames): those are the layouts the round-18 bounded contract accepts, so
    they must arrive in one strictly increasing run -- both ends echo in order.

    Requests 13..16 carry the largest legal UDP payload (1472 B / 1514 B frame),
    which the stack hands over as a two-mbuf chain. The driver refuses those
    BEFORE prepare() (no IOMemoryDescriptor, no command, no descriptor), so they
    are never transmitted; placing them last keeps the peer's in-order rule
    intact and makes the refusal a declared part of the batch instead of a gap.
    """
    if req not in REQUESTS:
        raise ValueError('round18 requires req 1..16')
    if req >= 13:
        return 1472
    if req % 3 == 2:
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
        raise ValueError('round18 requires a low-half nonzero token')
    size = length_of(req)
    header = struct.pack('>III', MAGIC, token, req)
    body = _stream(b'round18-std-tx-v1\x00' + header, size - len(header))
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
