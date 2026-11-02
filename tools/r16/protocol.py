#!/usr/bin/env python3
"""Round16 clean4 application bytes; shared by load, peer and independent decoder."""
import hashlib
import struct

MAGIC = 0x31424F49
REQUESTS = (1, 2, 3, 4)
SEED = bytes(1024)  # Preserve r15's nonmagic pre-window observation prefix.


def payload(token, req):
    if not 0 < token < 0x80000000 or req not in REQUESTS:
        raise ValueError('clean4 requires low-half nonzero token and req1..4')
    header = struct.pack('>III', MAGIC, token, req)
    padding = hashlib.sha256(b'round16-clean4-padding-v1\x00' + header).digest()[:20]
    return header + padding


def identify(data):
    if len(data) < 12:
        return None
    magic, token, req = struct.unpack_from('>III', data)
    return (token, req) if magic == MAGIC else None


def evidence(data):
    return 'len=%d sha256=%s payload=%s' % (
        len(data), hashlib.sha256(data).hexdigest(), data.hex())
