#!/usr/bin/env python3
"""Finite R52 streams reuse R45 payload hashing and R51 IPv6 receipts."""
import importlib.util
from pathlib import Path

_path = Path(__file__).resolve().parents[1] / 'tcp6_mixed/protocol.py'
_spec = importlib.util.spec_from_file_location('_r52_ipv6_payload_base', _path)
_base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_base)
_wire = _base._base
PHASE_CODES = ('a-before', 'b-before', 'b-during-down', 'a-after-up')
TRANSFERS = tuple((phase, direction, 8 << 20) for phase in PHASE_CODES
                  for direction in ('upload', 'download'))
_wire.MAGIC, _wire.PHASE_CODES, _wire.TRANSFERS = b'R52TCP1\0', PHASE_CODES, TRANSFERS
MAGIC, HEADER, CHUNK = _wire.MAGIC, _wire.HEADER, _wire.CHUNK
request, parse_request = _wire.request, _wire.parse_request
chunks, expected_digest = _wire.chunks, _wire.expected_digest
receive, send_json, receive_json = _wire.receive, _wire.send_json, _wire.receive_json
stream, transfer_record, validate_receipt = _wire.stream, _wire.transfer_record, _wire.validate_receipt
sockaddr, endpoint, transport = _base.sockaddr, _base.endpoint, _base.transport
validate_transport = _base.validate_transport


def transfers(mode, role=None):
    selected = TRANSFERS if mode == 'auto' else TRANSFERS[:4]
    return tuple(row for row in selected if role is None or row[0].startswith(role + '-'))
