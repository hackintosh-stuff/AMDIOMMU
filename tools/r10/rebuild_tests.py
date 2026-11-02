"""Rebuild tests/dma-observe-test.cpp from its round-10 parts.

The v2 test block lives in tools/r10/tests_v2.cpp so it can be edited without
hand-editing a 100 KB test file. This script replaces the region between the
first round-10 marker and `int main()`.
"""
import sys

P = 'tests/dma-observe-test.cpp'
NEW = 'tools/r10/tests_v2.cpp'
MARK = '// ---- ROUND 10: the v2 snapshot'
MARK_MAIN = 'int main() {'

s = open(P, encoding='utf-8').read()
i = s.find(MARK)
j = s.find(MARK_MAIN)
if i < 0 or j < 0 or j < i:
    print('refused: markers not found (i=%d j=%d)' % (i, j))
    sys.exit(1)
new = open(NEW, encoding='utf-8').read()
out = s[:i] + new + s[j:]
open(P, 'w', encoding='utf-8', newline='\n').write(out)
print('rebuilt %d -> %d bytes' % (len(s), len(out)))
