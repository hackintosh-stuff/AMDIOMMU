#!/usr/bin/env python3
"""Host-only tests of the actual m2b2Submit, with fake MMIO and DMA.
Run: python tests/command-ring-test.py --compiler clang++
No SDK, device, network or kext load required. Compiler must accept C++11.
"""
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'probe/AMDMapperProbeInternal.hpp').read_text(encoding='utf-8')

def extract(start, end):
    return SOURCE[SOURCE.index(start):SOURCE.index(end, SOURCE.index(start))]

PREFIX = r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
using UInt8=uint8_t; using UInt32=uint32_t; using UInt64=uint64_t;
#define M23_CMD_BUF_SIZE 8192
#define M2B1_LOOP_TIMEOUT 32
#define M2B2_CMD_LOG_MAX 4
#define M2B2_CMD_COMPL_WAIT 1
#define M2B2_OFF_CMD_HEAD 0
#define M2B2_OFF_CMD_TAIL 8
struct M2B2CmdRecord {
 const char *label; UInt32 d0,d1,d2,d3; UInt64 expected,observed;
 UInt32 loops; bool ok;
};
'''
MOCKS = r'''
static UInt32 memory[M23_CMD_BUF_SIZE/4+4];
static UInt64 semaphore, head;
static UInt32 reads, writes, descriptorWrites, barriers, delayedHead;
static bool consume=true, signal=true;
static UInt64 mmioRead64(volatile UInt8*, UInt32 off) {
 assert(off==M2B2_OFF_CMD_HEAD); ++reads;
 if(delayedHead && reads==3) head=delayedHead;
 return head;
}
static void OSSynchronizeIO() { ++barriers; }
static void m2b2WriteCmd(volatile UInt32 *buf, UInt32 i,
 UInt32 a, UInt32 b, UInt32 c, UInt32 d) {
 assert(i<M23_CMD_BUF_SIZE/16); ++descriptorWrites;
 buf[i*4]=a;buf[i*4+1]=b;buf[i*4+2]=c;buf[i*4+3]=d;
}
static void mmioWrite64(volatile UInt8*, UInt32 off, UInt64 tail) {
 assert(off==M2B2_OFF_CMD_TAIL && tail<M23_CMD_BUF_SIZE && !(tail&15));
 assert(barriers); ++writes;
 UInt32 cw=((UInt32)tail+M23_CMD_BUF_SIZE-16)%M23_CMD_BUF_SIZE/4;
 assert(memory[cw+1]>>28==M2B2_CMD_COMPL_WAIT);
 if(consume) head=tail;
 if(signal) semaphore=((UInt64)memory[cw+3]<<32)|memory[cw+2];
}
'''
MAIN = r'''
static M2B2CmdCtx fresh(UInt32 tail=0) {
 std::memset(memory,0,sizeof(memory));
 memory[M23_CMD_BUF_SIZE/4]=0xfeedbeef;
 semaphore=0; head=tail; reads=writes=descriptorWrites=barriers=delayedHead=0;
 consume=signal=true;
 M2B2CmdCtx c{}; c.buf=memory; c.sem=&semaphore; c.semPA=0x1000;
 c.tail=tail;c.idx=tail/16; return c;
}
static bool submit(M2B2CmdCtx &c) {
 return m2b2Submit(nullptr,&c,"mock",0,0x30000000,7,8);
}
int main() {
 // >160 lifetime submissions, repeated physical wraps, bounded log does not stop IO.
 auto c=fresh();
 for(unsigned i=0;i<2000;++i) {
  assert(submit(c)); assert(c.tail==((i+1)*32)%M23_CMD_BUF_SIZE);
  assert(c.completionSequence==i+1 && semaphore==i+1);
  assert(memory[M23_CMD_BUF_SIZE/4]==0xfeedbeef);
 }
 assert(c.wraps==7 && c.postWrapCompleted==1745 && c.recordCount==4);
 // Pair itself straddles last descriptor and slot zero.
 c=fresh(M23_CMD_BUF_SIZE-16); assert(submit(c));
 assert(c.tail==16 && c.wraps==1 && c.postWrapCompleted==1);
 // Full/one-free-slot cannot publish either descriptor; timeout poisons context.
 c=fresh();head=16;assert(!submit(c));
 assert(reads==M2B1_LOOP_TIMEOUT && !writes && !descriptorWrites && c.failed);
 assert(!submit(c) && !writes && !c.completionSequence);
 c=fresh();head=32;assert(!submit(c));assert(!descriptorWrites);
 // Consumer progress within finite reservation poll permits exactly one pair.
 c=fresh();head=16;delayedHead=48;assert(submit(c));assert(reads==3 && writes==1);
 // Invalid hardware pointer and inconsistent software cursor fail closed.
 c=fresh();head=3;assert(!submit(c));assert(!writes && !descriptorWrites);
 c=fresh();head=M23_CMD_BUF_SIZE;assert(!submit(c));assert(!writes);
 c=fresh();c.idx=1;assert(!submit(c));assert(!writes);
 // Stale completion cannot pass; never retry unknown hardware outcome.
 c=fresh();signal=false;assert(!submit(c));assert(writes==1 && c.lastLoops==M2B1_LOOP_TIMEOUT);
 assert(c.submits==1 && !c.completed && !submit(c) && writes==1);
 // Completion number is independent of ring index and diagnostic submits.
 c=fresh();c.submits=0xffffffffU;c.completionSequence=0x100000000ULL;
 assert(submit(c) && semaphore==0x100000001ULL);
 c=fresh();c.completionSequence=~UInt64(0);assert(!submit(c));assert(!writes);
 std::puts("actual m2b2Submit fake-MMIO tests: PASS");
}
'''

def geometry_test():
    # Exhaust the configured production capacity, not an enlarged test ring.
    import re
    capacity = int(re.search(r'#define M23_CMD_BUF_SIZE\s+(\d+)', SOURCE).group(1))
    assert '((UInt32)head + bytes - c->tail - 16) & (bytes - 1)' in SOURCE
    slots = capacity // 16
    for h in range(slots):
        for t in range(slots):
            head, tail = h * 16, t * 16
            free_bytes = (head + capacity - tail - 16) & (capacity - 1)
            assert free_bytes // 16 == (h - t - 1) % slots
            if free_bytes >= 32:
                occupied = (t - h) % slots
                assert occupied + 2 <= slots - 1
                assert (t + 1) % slots != h or occupied == 0
                assert ((t + 2) % slots) * 16 < capacity
    print(f'Production ring geometry: PASS ({slots * slots} HEAD/TAIL states)')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', default=shutil.which('clang++') or shutil.which('g++'))
    parser.add_argument('--emit', type=Path, help='emit standalone C++ harness instead of running')
    parser.add_argument('--geometry-only', action='store_true', help='exhaustive arithmetic check; no compiler required')
    args = parser.parse_args()
    geometry_test()
    if args.geometry_only:
        return
    text = PREFIX + extract('struct M2B2CmdCtx {', '// ---- m2b2ResetEventLog') + MOCKS
    text += extract('static inline bool m2b2Submit(', '// ---- m2b2ReadBar64') + MAIN
    if args.emit:
        args.emit.write_text(text, encoding='utf-8')
        return
    if not args.compiler:
        parser.error('No host C++ compiler found; supply --compiler or --emit to run elsewhere')
    with tempfile.TemporaryDirectory(prefix='amd-command-ring-') as tmp:
        source = Path(tmp) / 'test.cpp'
        binary = Path(tmp) / 'test.exe'
        source.write_text(text, encoding='utf-8')
        subprocess.run([args.compiler, '-std=c++11', '-Wall', '-Wextra', '-Werror',
                        str(source), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)

if __name__ == '__main__':
    main()
