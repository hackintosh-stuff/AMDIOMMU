#!/usr/bin/env python3
"""Run the accepted mixed-device workload with the R54 requester-claim profile."""
from pathlib import Path
import sys

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[1] / 'r53'))
import common

RUN = common.MixedRun(54, 'a798b47a9daaae98d5d4efe98285c1bfbee9da2d',
                      {'RTL812xLucy': '1.1.239', 'AMDMapperProbe': '0.61.0',
                       'RealtekRTL8111': '3.0.54'}, 0x54c0de54,
                      parent='set-on-client-claim-before-pci-open', runner=HERE)
COMMANDS = ('peer', 'load', 'deploy', 'capture', 'analyze', 'disarm-next')


def main(run=RUN):
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print('usage: run.py {%s} [arguments]' % ','.join(COMMANDS))
        return 0 if sys.argv[1:] in (['-h'], ['--help']) else 2
    command = sys.argv.pop(1)
    common.select_run(run)
    # Keep the finite protocol, real snapshot retake, and page-table checks shared.
    if command == 'peer':
        return common.module('_mixed_peer', 'tools/r52/peer.py').main(default_token=run.token)
    if command == 'load':
        return common.module('_mixed_load', 'tools/r52/load.py').main(
            round_id=run.number, default_token=run.token)
    if command == 'capture':
        return common.module('_mixed_capture', 'tools/r52/capture.py').main(
            round_id=run.number, abi='mixed-RTL8111-RTL8125-mapper-ABI%d' % run.abi)
    return common.module('_mixed_entry', 'tools/r53/' + command + '.py').main()


if __name__ == '__main__':
    raise SystemExit(main())
