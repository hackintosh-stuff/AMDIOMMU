#!/usr/bin/env python3
"""Check bounded history/active slot separation; optional host C++ helper test.
python tests/tx-history-test.py --compiler clang++
python tests/tx-history-test.py --emit /tmp/tx-history.cpp
"""
from pathlib import Path
import argparse
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TX = (ROOT/'kext/AMDMapperProbeTxDebug.cpp').read_text(encoding='utf-8')
HEADER = (ROOT/'tools/lucy-obs/AMDAliveTxDomainNative.hpp').read_text(encoding='utf-8')

def contracts():
    assert TX.count('r25Archive(s,w);') == 2
    assert TX.count('s.records[') == 1  # only archive writes history
    for obsolete in ('submitBudget', 'kR17SubmitBudget', 's.records[h - 1]', 's.records[s.count++]',
                     'r->handle>s.count', 'h > s.count', 'command.idx +', 'ctx.idx+2'):
        assert obsolete not in TX, obsolete
    assert 'r->reqId>r17tx::kRequestLimit' in TX
    assert '((UInt64)d->handleCounter << 32)' in TX
    assert TX.count('auto &w=d->slotRecord[slot]') == 2
    assert TX.count('auto &w = d->slotRecord[slot]') == 2
    print('Tx admission/routing source contracts: PASS')

MAIN = r'''
#include <cassert>
#include <cstdio>
int main() {
 static_assert(r17domain::kVersion == 3, "domain ABI version");
 r17domain::Snapshot s{};
 r17domain::Record live[4]{};
 unsigned long long issued=0;
 // Keep four active records, retire out of issue order, repeat past history capacity.
 const unsigned order[4]={2,0,3,1};
 for(unsigned batch=0;batch<250;++batch) {
  for(unsigned k=0;k<4;++k) { live[k]={}; live[k].handle=++issued;live[k].status=1; }
  for(unsigned n=0;n<4;++n) {
   unsigned k=order[n];live[k].status=3;
   unsigned before=s.historyTotal;
   r25Archive(s,live[k]);
   assert(s.historyTotal==before+1);
   assert(s.count==(s.historyTotal<32?s.historyTotal:32));
   assert(s.historyStart+s.count==s.historyTotal);
   assert(s.records[before%32].handle==live[k].handle);
   for(unsigned j=n+1;j<4;++j) {
    unsigned other=order[j];
    assert(live[other].status==1 && live[other].handle==batch*4+other+1);
   }
  }
 }
 assert(s.historyTotal==1000 && s.count==32 && s.historyStart==968);
 for(unsigned n=0;n<32;++n) {
  unsigned seq=s.historyStart+n;
  const auto &r=s.records[seq%32];
  assert(r.handle==(seq/4)*4+order[seq%4]+1 && r.status==3);
 }
 // Failed/unconfirmed retirement is not archived: live owner remains authoritative.
 live[1].handle=1001;live[1].status=9;
 assert(s.historyTotal==1000 && live[1].handle==1001);
 std::puts("actual r25Archive circular-history tests: PASS (1000 retirements)");
}
'''

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--compiler', default=shutil.which('clang++') or shutil.which('g++'))
    p.add_argument('--emit', type=Path)
    p.add_argument('--contracts-only', action='store_true')
    args=p.parse_args()
    contracts()
    if args.contracts_only:
        return
    start=TX.index('static void r25Archive(')
    helper=TX[start:TX.index('static bool r17Invalidate(',start)]
    text='#include <cstdint>\nusing UInt64=uint64_t;\n'+HEADER.replace('#pragma once','')+helper+MAIN
    if args.emit:
        args.emit.write_text(text,encoding='utf-8')
        return
    if not args.compiler:
        p.error('No host C++ compiler; use --compiler or --emit')
    with tempfile.TemporaryDirectory(prefix='amd-tx-history-') as tmp:
        source=Path(tmp)/'test.cpp';binary=Path(tmp)/'test.exe'
        source.write_text(text,encoding='utf-8')
        subprocess.run([args.compiler,'-std=c++11','-Wall','-Wextra','-Werror',str(source),'-o',str(binary)],check=True)
        subprocess.run([str(binary)],check=True)

if __name__=='__main__':
    main()
