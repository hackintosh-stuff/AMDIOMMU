#!/usr/bin/env python3
"""Capture all three R53 bundle identities and each selected driver's native evidence."""
from common import module
_base = module('_r53_capture_base', 'tools/mixed/capture.py')

def main():
    return _base.main(round_id=53, abi='mixed-RTL8111-RTL8125-mapper-ABI2')

if __name__ == '__main__':
    raise SystemExit(main())
