"""Replace the round-9 record-decoding tests with the round-10 v2 suite."""
import sys

P = 'tests/dma-observe-test.cpp'
NEW = 'tools/r10/tests_v2.cpp'

MARK_OLD = '// ---- ROUND 9: decoding and joining the driver\'s own records'
MARK_MAIN = 'int main() {'

s = open(P, encoding='utf-8').read()
i = s.find(MARK_OLD)
j = s.find(MARK_MAIN)
if i < 0 or j < 0:
    print('refused: markers not found (i=%d j=%d)' % (i, j))
    sys.exit(1)
new = open(NEW, encoding='utf-8').read()
out = s[:i] + new + s[j:]
open(P, 'w', encoding='utf-8', newline='\n').write(out)
print('replaced %d -> %d bytes' % (len(s), len(out)))
