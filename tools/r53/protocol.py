#!/usr/bin/env python3
"""R53 uses the accepted finite dual-endpoint streams with a distinct wire identity."""
import importlib.util
from pathlib import Path
_path = Path(__file__).resolve().parents[1] / 'r52/protocol.py'
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
