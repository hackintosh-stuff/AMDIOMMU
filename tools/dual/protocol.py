#!/usr/bin/env python3
"""R53 uses the accepted finite dual-endpoint streams with a distinct wire identity."""
import importlib.util
from pathlib import Path
_path = Path(__file__).resolve().parents[1] / 'mixed/protocol.py'
_spec = importlib.util.spec_from_file_location('_r53_protocol_base', _path)
_base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_base)
_base._wire.MAGIC = b'R53TCP1\0'
MAGIC = _base._wire.MAGIC
for _name in ('HEADER', 'CHUNK', 'TRANSFERS', 'PHASE_CODES', 'request', 'parse_request',
              'chunks', 'expected_digest', 'receive', 'send_json', 'receive_json',
              'stream', 'transfer_record', 'validate_receipt', 'sockaddr', 'endpoint',
              'transport', 'validate_transport', 'transfers'):
    globals()[_name] = getattr(_base, _name)

def select_cycles(reciprocal):
    """Keep historical seed bytes; R60 adds a reciprocal pair to the finite protocol."""
    global MAGIC, PHASE_CODES, TRANSFERS
    MAGIC = b'R60TCP1\0' if reciprocal else b'R53TCP1\0'
    PHASE_CODES = _base.PHASE_CODES + (('a-during-b-down', 'b-after-up') if reciprocal else ())
    TRANSFERS = tuple((phase, direction, 8 << 20) for phase in PHASE_CODES
                      for direction in ('upload', 'download'))
    _base._wire.MAGIC, _base._wire.PHASE_CODES = MAGIC, PHASE_CODES
    # The finite peer's transfers() selects from _base; request/parse/hash use _wire.
    _base.TRANSFERS = _base._wire.TRANSFERS = TRANSFERS
