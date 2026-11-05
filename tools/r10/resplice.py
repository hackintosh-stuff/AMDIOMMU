"""HISTORICAL ONE-SHOT SCRIPT -- do not use as a current entry point.

Round 10 used this to re-splice two probe blocks into the single
kext/AMDMapperProbe.cpp by matching text markers. Round 11 split
that file into eight modules, so the markers no longer exist and
re-splicing into the entry module is not a meaningful operation:
the blocks live in AMDMapperProbeNic.cpp and AMDMapperProbeObsDebug.cpp
now, and the round-11 split checker that used to validate the result
(tools/r11/verify-split.py) has since been retired because its original-line
markers no longer match the refactored tree.

Kept for the record of how round 10 was built. Running it will
refuse, because its markers are gone.
"""
import re
import sys

CPP = 'kext/AMDMapperProbe.cpp'
IDENT = 'tools/r10/probe_nic_identity.cpp'
OBS = 'tools/r10/probe_obs_v2.cpp'

IDENT_START = ('// ===========================================================================\n'
               '// \u7b2c\u5341\u8f6e\uff1a\u91c7\u96c6\u76ee\u6807\u7f51\u5361\u7684\u8eab\u4efd\n')
OBS_START = ('// ===========================================================================\n'
             '// \u7b2c\u5341\u8f6e\uff1a\u8bfb\u9a71\u52a8\u4fa7\u89c2\u6d4b\u65e5\u5fd7\uff08\u7ebf\u683c\u5f0f v2\uff09\n')
OBS_END_MARK = '\nvoid org_example_AMDMapperProbe::m2b2PublishDmaDefaults()'


def main():
    s = open(CPP, encoding='utf-8').read()
    ident = open(IDENT, encoding='utf-8').read()
    obs = open(OBS, encoding='utf-8').read()

    i = s.find(IDENT_START)
    j = s.find(OBS_START)
    k = s.find(OBS_END_MARK)
    if i < 0 or j < 0 or k < 0:
        print('refused: markers not found (i=%d j=%d k=%d)' % (i, j, k))
        return 1
    if not (i < j < k):
        print('refused: markers out of order')
        return 1

    out = s[:i] + ident + obs + s[k:]
    open(CPP, 'w', encoding='utf-8', newline='\n').write(out)
    print('re-spliced: %d -> %d bytes' % (len(s), len(out)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
