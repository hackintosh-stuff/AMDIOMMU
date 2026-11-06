#!/usr/bin/env python3
"""Round25: 512 monotonic requests, 16 sends then receives per group.

The original mixed 16-request length pattern repeats; four live mapping slots
must recycle in one domain window, without controlled-request retries.
"""
import hashlib
import struct

MAGIC = 0x31424F49  # 'IOB1': same business magic the driver's obsParseBiz looks for
REQUESTS = tuple(range(1, 513))
SEED = bytes(1024)  # r15's nonmagic pre-window observation prefix, unchanged
LARGE = (2, 4, 6, 8, 11)

# Deliberately exceeds the four live-mapping slots; no client pacing workaround.
BURST = 16  # Send every member before collecting any echo; never retransmit.


def bursts():
    """32 consecutive groups, each containing 16 monotonic request ids."""
    return [REQUESTS[i:i + BURST] for i in range(0, len(REQUESTS), BURST)]


def length_of(req):
    """Repeat the original 16 mixed lengths without repeating request ids."""
    if req not in REQUESTS:
        raise ValueError('round25 requires req 1..512')
    pattern_req = (req - 1) % 16 + 1
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
        raise ValueError('round25 requires a low-half nonzero token')
    size = length_of(req)
    header = struct.pack('>III', MAGIC, token, req)
    body = _stream(b'round23-multi-inflight-v1\x00' + header, size - len(header))
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


# ---- ordinary traffic probes (unchanged from round 22) ----------------------
ORD_MAGIC = 0x3144524F  # 'ORD1'
ORD_SIZE = 200


def ordinary(seq):
    """A plain UDP payload that is distinguishable in the logs but not selected."""
    if not 0 < seq < 1 << 32:
        raise ValueError('ordinary seq out of range')
    head = struct.pack('>III', ORD_MAGIC, seq, 0)
    body = _stream(b'round22-ordinary-v1\x00' + head, ORD_SIZE - len(head))
    return head + body


def ordinary_seq(data):
    """seq of an ordinary probe, or None if this is not one."""
    if len(data) < 12:
        return None
    magic, seq, _ = struct.unpack_from('>III', data)
    return seq if magic == ORD_MAGIC else None
