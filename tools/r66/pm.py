#!/usr/bin/env python3
"""Explicitly arm/disarm dual-domain system PM for one controlled sleep cycle."""
import argparse
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'r31'))
from session import set_boolean_property

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('arm','disarm'))
    args=parser.parse_args()
    armed=args.action=='arm'
    set_boolean_property('R66ArmSystemPM', value=armed)
    print('R66 coordinated system PM '+('armed' if armed else 'disarmed'))

if __name__=='__main__':
    main()
