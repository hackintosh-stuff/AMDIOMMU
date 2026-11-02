#!/usr/bin/env python3
"""patch-deploy-r12.py -- add the round-12 gate checks to deploy-r12.sh.

WHY
---
Round 11's deploy script asserted that the probe carried round 11's entry
points. Round 12 added the evidence gate and the strict batch spec, and both are
HEADER-INLINE: they have no symbol to look for. So a probe built from a tree
that still had round 11's verdict would deploy without complaint and then judge
by round 11's weaker rules -- which is the same "every layer says OK, the
evidence is weaker than claimed" failure this project keeps finding.

What IS observable in the binary is the stable reason tokens the gate publishes.
Their presence is evidence that the gate is compiled in; their absence is
evidence that it is not.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
TARGET = os.path.join(ROOT, 'tools', 'deploy-r12.sh')

ANCHOR = 'echo "== after =="\n'

INSERT = '''# ---- round 12: the probe must carry the evidence gate -------------------
#
# The PASS-CANDIDATE branch now calls amdobs::obsEvidenceGate(), and the
# production read path uses the STRICT batch spec. Both are new in round 12, so
# a probe without them would deploy fine and judge by round 11's weaker rules.
#
# They are header-inline, so there is no symbol to look for. What IS observable
# in the binary is the stable reason tokens the gate publishes. Their presence
# is evidence the gate is compiled in; their absence is evidence it is not.
for tok in identity-unknown page-table-evidence-failed \\
           token-not-resolved-on-declaration records-dropped-by-writer; do
    if ! strings "$PRB_BIN" | grep -q "$tok"; then
        echo "FAIL: the probe does not carry the round-12 evidence gate"
        echo "      (no '$tok' token: it would judge by round 11's rules)"
        exit 1
    fi
done
echo "probe carries the round-12 evidence gate OK"

# The driver must carry the round-12 write protocol: atomic word stores and
# atomic loss counters. Round 11's publisher copied bytes with plain loads,
# which is a data race against the writer -- proven by TSan on the shared
# implementation. There is no runtime symbol for it, so the header's own
# identity strings are checked instead.
if ! strings "$DRV_BIN" | grep -q 'RTL812xObsWrite'; then
    echo "NOTE: the write protocol header name is not in the driver strings."
    echo "      It may be fully inlined; the host test covers the protocol."
fi

echo "== after =="
'''


def main():
    with open(TARGET, encoding='utf-8', newline='') as f:
        src = f.read()
    if '\r' in src:
        print('REFUSED: the target contains CR bytes')
        return 1
    if src.count(ANCHOR) != 1:
        print('REFUSED: the anchor appears %d times' % src.count(ANCHOR))
        return 1
    src = src.replace(ANCHOR, INSERT, 1)
    with open(TARGET, 'w', encoding='utf-8', newline='') as f:
        f.write(src)
    print('added the round-12 gate checks to deploy-r12.sh')
    return 0


if __name__ == '__main__':
    sys.exit(main())
