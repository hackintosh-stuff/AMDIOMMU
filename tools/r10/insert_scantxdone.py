"""Insert the reconstructed m2b2ScanTxDone() before the round-10 obs reader.

The function was lost by a splice whose end marker sat after it. It goes back
immediately before the round-10 identity block, which is where the splice
boundary is, so a future re-splice cannot swallow it again.
"""
import sys

P = 'kext/AMDMapperProbe.cpp'
NEW = 'tools/r10/probe_scantxdone.cpp'
MARK = ('// ===========================================================================\n'
        '// \u7b2c\u5341\u8f6e\uff1a\u91c7\u96c6\u76ee\u6807\u7f51\u5361\u7684\u8eab\u4efd\n')

s = open(P, encoding='utf-8').read()
if 'm2b2ScanTxDone() {' in s:
    print('already present')
    sys.exit(0)
i = s.find(MARK)
if i < 0:
    print('refused: round-10 identity marker not found')
    sys.exit(1)
new = open(NEW, encoding='utf-8').read()
out = s[:i] + new + s[i:]
open(P, 'w', encoding='utf-8', newline='\n').write(out)
print('inserted m2b2ScanTxDone: %d -> %d bytes' % (len(s), len(out)))
