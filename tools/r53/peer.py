#!/usr/bin/env python3
"""Finite R53 role peer; no additional network protocol or workload matrix."""
from common import module
_base = module('_r53_peer_base', 'tools/r52/peer.py')
serve = _base.serve

def main():
    return _base.main(default_token=0x53c0de53)

if __name__ == '__main__':
    raise SystemExit(main())
