#!/usr/bin/env python3
"""R53 mixed-driver traffic uses the accepted finite parallel/lifecycle workload."""
from common import module
_base = module('_r53_load_base', 'tools/mixed/load.py')
transfer, before_traffic = _base.transfer, _base.before_traffic

def main():
    return _base.main(round_id=53, default_token=0x53c0de53)

if __name__ == '__main__':
    raise SystemExit(main())
