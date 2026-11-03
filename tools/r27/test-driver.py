#!/usr/bin/env python3
"""Compile and exercise the actual generated Round34 RX call sites and the retained RX4 methods.

This is one RX ownership/lifecycle check, not a replay of previous rounds.
--source additionally checks the newly generated Lucy call sites, and uses its
actual methods in the harness.  Compiler: CXX, then clang++, then g++.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def method(text, name):
    match = re.search(r'^(?:void|bool|IOReturn|mbuf_t) RTL8125::' + name + r'\(', text, re.M)
    if not match:
        raise AssertionError('missing actual method ' + name)
    start = text.index('{', match.start())
    depth = 0
    for end in range(start, len(text)):
        depth += (text[end] == '{') - (text[end] == '}')
        if depth == 0:
            return text[match.start():end + 1]
    raise AssertionError('unterminated actual method ' + name)


PREFIX = r'''
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include "RTL812xRxPool.hpp"
#include "RTL812xRxMap.hpp"
using UInt8 = unsigned char;
using UInt32 = unsigned int;
using UInt64 = unsigned long long;
using IOReturn = int;
struct OSObject {};
struct IOBufferMemoryDescriptor {};
enum { kIOReturnSuccess=0, kIOReturnBadArgument=1, kIOReturnNotReady=2,
       kIOReturnBusy=3, kIOReturnUnsupported=4, kNumTxDesc=1024,
       kRxBufferSize=4096, MBUF_DONTWAIT=0, RxRES=0x00200000,
       DescOwn=0x80000000u };
static UInt64 tick = 10000;
static UInt64 mach_absolute_time() { return ++tick; }
static UInt64 OSSwapLittleToHostInt64(UInt64 v) { return v; }
struct Mbuf { unsigned char bytes[4096]; unsigned int len, pktlen; Mbuf *next; };
using mbuf_t = Mbuf *;
static mbuf_t mbuf_next(mbuf_t m) { return m->next; }
static unsigned int mbuf_len(mbuf_t m) { return m->len; }
static unsigned int mbuf_pkthdr_len(mbuf_t m) { return m->pktlen; }
static void *mbuf_data(mbuf_t m) { return m->bytes; }
static unsigned int mbuf_trailingspace(mbuf_t) { return 4096; }
static void mbuf_copy_pkthdr(mbuf_t dst, mbuf_t src) { dst->pktlen=src->pktlen; }
static void mbuf_pkthdr_setheader(mbuf_t, void *) {}
static void mbuf_freem_list(mbuf_t) {}
static unsigned int releases = 0;
static void r15ReleaseOwned(mbuf_t, IOBufferMemoryDescriptor *) { releases++; }
static void IOFree(void *p, unsigned long) { std::free(p); }
struct Pool { bool fail; Mbuf out;
    mbuf_t getPacket(UInt32, int) { return fail ? nullptr : &out; }
};
struct Buffer { mbuf_t mbuf; UInt64 phyAddr; };
struct Desc { struct { UInt64 blen, addr; } buf; };
class RTL8125 {
public:
    struct R15PoolState;
    R15PoolState *r15Pool;
    Buffer *rxBufArray;
    Desc *rxDescArray;
    Pool *rxPool;
    IOReturn r27RxControl(r27rx::Request *);
    void r27RxRearm(UInt32, UInt64, UInt32, UInt32, UInt32, UInt32, UInt64 *);
    void r27RxPosted(UInt32, UInt64);
    bool r27RxActive();
    bool r27RxParse(mbuf_t, UInt32 *, UInt32 *);
    void r15PoolRearm(UInt32, UInt64, UInt32, UInt32, UInt32, UInt32, UInt64 *);
    void r15PoolPosted(UInt32, UInt64);
    mbuf_t r15PoolCopy(mbuf_t, UInt32);
    void r15PoolFree();
    bool r34RxOwnsRing() const { return false; }
    bool r34RxFree() { return true; }
    void setProperty(const char *, UInt64, unsigned int) {}
    void setProperty(const char *, const char *) {}
};
'''

SUFFIX = r'''
struct Fixture {
    RTL8125 d;
    Mbuf *buffers;
    Buffer ring[1024];
    Desc desc[1024];
    Pool pool{};
    r27rx::Request q{};
    Fixture() {
        buffers = new Mbuf[r15pool::kMaxEntries]();
        d.r15Pool = (RTL8125::R15PoolState *)std::calloc(1, sizeof(*d.r15Pool));
        d.rxBufArray=ring; d.rxDescArray=desc; d.rxPool=&pool;
        auto &p=*d.r15Pool;
        p.snap.version=r15pool::kVersion; p.snap.bytes=sizeof(p.snap);
        p.snap.state=r15pool::kPrepared; p.snap.generation=7;
        p.snap.poolId=999; p.snap.tPrepared=100;
        p.snap.entryCount=r15pool::kMaxEntries; p.snap.spareCount=r27rx::kCount;
        p.snap.reserved[0]=0x27abcd;
        for (UInt32 i=0; i<r15pool::kMaxEntries; ++i) {
            const bool spare=i>=r15pool::kRingCount;
            auto &e=p.snap.entries[i];
            e.addr=0x200000000ULL+(UInt64)i*8192ULL+(spare ? 128 : 0);
            e.capacity=4096; e.id=i;
            e.kind=spare?r15pool::kEntrySpare:r15pool::kEntryRing;
            p.mbufs[i]=&buffers[i];
            if (!spare) { p.slotId[i]=i; ring[i]={p.mbufs[i],e.addr}; desc[i].buf={DescOwn,e.addr}; }
        }
        q.version=r27rx::kVersion; q.bytes=sizeof(q); q.poolId=p.snap.poolId;
        q.expectedGeneration=p.snap.generation; q.businessToken=p.snap.reserved[0];
    }
    ~Fixture() { std::free(d.r15Pool); delete[] buffers; }
    void op(UInt32 op) { q.op=op; assert(d.r27RxControl(&q)==kIOReturnSuccess); }
    void install() {
        op(r27rx::kHold); assert(d.r15Pool->rx27BindingsHeld);
        q.mapCount=q.replaceLimit=r27rx::kCount;
        for (UInt32 i=0; i<r27rx::kCount; ++i) {
            auto &e=d.r15Pool->snap.entries[r15pool::kRingCount+i];
            q.maps[i]={e.addr,r27rx::kIovaBase+(UInt64)i*8192+(e.addr&4095),200+i,e.id,e.capacity};
        }
        op(r27rx::kInstall);
        d.r15Pool->snap.state=r15pool::kAuthorized;
        d.r15Pool->snap.replaceLimit=r27rx::kCount;
        d.r15Pool->snap.deadline=tick+100000;
    }
    UInt64 receive(UInt32 slot, UInt32 token=0, UInt32 req=0) {
        const UInt64 old=ring[slot].phyAddr;
        desc[slot].buf.blen=0; // completed descriptor; NIC no longer owns it
        UInt64 addr=old;
        d.r15PoolRearm(slot,old,0,166,token,req,&addr);
        return addr;
    }
    void post(UInt32 slot, UInt64 addr) {
        desc[slot].buf.addr=addr; desc[slot].buf.blen=DescOwn|4096;
        d.r15PoolPosted(slot,addr);
    }
};

int main() {
    static_assert(r27rx::kVersion==4 && (int)r27rx::kCount==(int)r15pool::kRingCount);
    static_assert(r15pool::kVersion==2 && (int)r15pool::kSpareCount==(int)r27rx::kCount);
    static_assert(sizeof(r27rx::Cycle)==40);
    static_assert(sizeof(r27rx::Witness)==272 && offsetof(r27rx::Witness,tLastPost)==80);
    static_assert(offsetof(r27rx::Witness,samples)==112);
    static_assert(sizeof(r27rx::Snapshot)==311376 && sizeof(r27rx::Request)==344192);
    static_assert(sizeof(r27rx::BackendSnapshot)==204864);
    {
        Fixture f; f.install();
        auto &p=*f.d.r15Pool;
        for (UInt32 i=0; i<r27rx::kCount; ++i) {
            const UInt64 addr=f.receive(i);
            assert(addr==f.q.maps[i].iova && addr!=f.q.maps[i].pa);
            assert(!p.rx27.witnesses[i].tPost);
            f.post(i,addr);
        }
        assert(p.rx27.posted==r27rx::kCount && p.rx27.pendingPosted==r27rx::kCount);
        // Legacy deadline is not a cyclic selector. Tokens do not select either.
        p.snap.deadline=1;
        for (UInt32 cycle=1; cycle<=4; ++cycle) {
            for (UInt32 i=0; i<r27rx::kCount; ++i) {
                auto addr=f.receive(i,cycle%2 ? 0 : 0x27abcd,cycle*100+i);
                assert(addr==f.q.maps[i].iova && p.rx27.pendingPosted==r27rx::kCount);
                f.post(i,addr);
                auto &w=p.rx27.witnesses[i];
                assert(w.postCount==cycle+1 && w.doneCount==cycle);
                assert(w.reuseCount==cycle && w.sampleCount<=4);
            }
        }
        assert(p.rx27.posted==5*r27rx::kCount && p.rx27.completed==4*r27rx::kCount);
        assert(p.snap.replacements==r27rx::kCount && p.snap.completions==4*r27rx::kCount);
        f.q.op=r27rx::kRelease;
        assert(f.d.r27RxControl(&f.q)==kIOReturnBusy);
        f.op(r27rx::kDisarm);
        const auto disarmed=p.rx27.tDisarmed;
        UInt64 addr=0;
        for (UInt32 i=0; i<r27rx::kCount; ++i) {
            addr=f.receive(i);
            assert(addr==p.snap.entries[i].addr);
            f.post(i,addr);
        }
        assert(p.rx27.posted==5*r27rx::kCount && p.rx27.completed==5*r27rx::kCount && p.rx27.restored==r27rx::kCount && !p.rx27.pendingPosted);
        assert(!p.rx27.flags);
        for (UInt32 i=0; i<r27rx::kCount; ++i) {
            auto &w=p.rx27.witnesses[i];
            assert(w.flags==7 && w.tPost<w.tDone && w.tDone<w.tRestoreOwn);
            assert(w.postCount==5 && w.doneCount==5 && w.reuseCount==4 && w.sampleCount==4);
            assert(w.tDone==w.tLastDone && w.samples[0].tDone<w.tDone);
            assert(w.tLastPost<=disarmed && w.tLastDone>w.tLastPost && w.tLastDone<w.tRestoreOwn);
            for (UInt32 c=0;c<4;++c) {
                assert(w.samples[c].cycle==c+1 && w.samples[c].flags==3);
                assert(w.samples[c].tPost<w.samples[c].tDone);
                if (c) assert(w.samples[c-1].tDone<w.samples[c].tPost);
            }
            assert(p.slotId[i]==i && !p.slotWitness[i]);
            assert(f.ring[i].mbuf==p.mbufs[i] && f.desc[i].buf.addr==w.originalPA);
        }
        f.op(r27rx::kDrain); assert(f.q.out.state==r27rx::kDrained);
        f.op(r27rx::kRelease); assert(!p.rx27BindingsHeld);
        assert(p.rx27.state==r27rx::kReleased);
        // Release must not re-enter the old permanent-spare R15 path.
        addr=f.receive(70); f.post(70,addr);
        assert(addr==p.snap.entries[70].addr && p.snap.replacements==r27rx::kCount);
    }
    {
        Fixture f; f.install(); auto &p=*f.d.r15Pool;
        auto addr=f.receive(4); f.post(4,addr);
        f.pool.fail=true;
        assert(!f.d.r15PoolCopy(f.ring[4].mbuf,166));
        addr=f.receive(4); f.post(4,addr);
        auto &w=p.rx27.witnesses[0];
        assert((w.flags&r27rx::kWitnessError) && w.tRestoreOwn);
        assert((p.rx27.flags&r27rx::kFlagCopyFailed) && !p.rx27.pendingPosted);
        assert(addr==p.snap.entries[4].addr && !p.rx27CopyFailed && releases==0);
        assert(p.snap.state==r15pool::kDisarmed && p.rx27.tDisarmed);
        addr=f.receive(5); f.post(5,addr);
        assert(addr==p.snap.entries[5].addr && p.snap.replacements==1);
        f.op(r27rx::kDisarm); f.op(r27rx::kDrain); f.op(r27rx::kRelease);
    }
    {
        Fixture f; f.install(); auto &p=*f.d.r15Pool;
        auto addr=f.receive(2); f.post(2,addr);
        f.desc[2].buf.addr ^= 4096;
        addr=f.receive(2);
        assert(addr==p.snap.entries[2].addr && p.rx27.pendingPosted==1);
        assert(p.rx27.flags&r27rx::kFlagAddressMismatch);
        assert(p.snap.state==r15pool::kDisarmed && p.rx27.tDisarmed);
        f.post(2,addr);
        assert(p.rx27.posted==1 && p.rx27.completed==1 && p.rx27.restored==1);
        auto physical=f.receive(3); f.post(3,physical);
        assert(physical==p.snap.entries[3].addr && p.snap.replacements==1);
        f.op(r27rx::kDrain); f.op(r27rx::kRelease);
    }
    {
        Fixture f; f.install(); auto &p=*f.d.r15Pool;
        auto addr=f.receive(0); f.post(0,addr);
        f.op(r27rx::kDrain); assert(p.rx27.state==r27rx::kDisarmed);
        addr=f.receive(0);
        assert(addr==p.snap.entries[0].addr && p.rx27.pendingPosted==1);
        f.post(0,addr);
        f.op(r27rx::kDrain);
        assert(p.rx27.posted==1 && p.rx27.completed==1 && p.rx27.restored==1);
        f.op(r27rx::kRelease);
    }
    {
        Fixture f;
        f.op(r27rx::kHold);
        f.d.r15PoolFree(); // stop before Install must retain physical MD backing
        assert(releases==0 && f.d.r15Pool->rx27BindingsHeld);
        assert(f.d.r15Pool->rx27.flags&r27rx::kFlagStopped);
        for (auto &b:f.ring) assert(!b.mbuf && !b.phyAddr);
    }
    {
        Fixture f; f.install();
        Mbuf m{}; m.len=m.pktlen=74;
        m.bytes[12]=8; m.bytes[14]=0x45; m.bytes[17]=60; m.bytes[23]=17;
        m.bytes[39]=40; std::memcpy(m.bytes+42,"R27P",4);
        m.bytes[47]=0x27; m.bytes[48]=0xab; m.bytes[49]=0xcd;
        m.bytes[52]=4; m.bytes[53]=1;
        UInt32 token=0,req=0;
        assert(f.d.r27RxParse(&m,&token,&req) && token==0x27abcd && req==1025);
        m.bytes[45]='X'; token=req=0;
        assert(!f.d.r27RxParse(&m,&token,&req) && !token && !req);
        // The actual normal receive parser sees the done echo after kRelease.
        m.len=m.pktlen=54; m.bytes[17]=40; m.bytes[39]=20;
        std::memcpy(m.bytes+42,"R29D",4); m.bytes[52]=0; m.bytes[53]=16;
        f.op(r27rx::kDrain); f.op(r27rx::kRelease);
        assert(f.d.r15Pool->rx27.state==r27rx::kReleased);
        assert(!f.d.r27RxParse(&m,&token,&req) && !token && !req);
        assert(f.d.r15Pool->rx27.tailSeq==16);
    }
    std::puts("R30 RX: all 1024 ring slots, 5120 cumulative DMA cycles, first4 samples per slot; physical-OWN restore; R27P observation; R29D only after release; RX4/pool2 ABI PASS");
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--emit', action='store_true')
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('r27_lucy_generator', ROOT / 'tools/apply-lucy-obs2.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.select_tx('21'); module.select_rx('34')
    template = module.POOL_METHODS
    text = template
    names = ('r27RxControl', 'r27RxRearm', 'r27RxPosted', 'r27RxActive', 'r27RxParse',
             'r15PoolRearm', 'r15PoolPosted', 'r15PoolCopy', 'r15PoolFree')
    norm = lambda value: re.sub(r'\s+', ' ', value).strip()
    if args.source:
        source = args.source if args.source.is_absolute() else ROOT / args.source
        text = source.read_text()
        assert norm(module.RX_NEW) in norm(text), 'actual RX rearm/OWN/post call sites differ'
        assert norm(module.RX_BIZ_NEW) in norm(text), 'actual R27P observation call site differs'
        assert norm(module.RX_DECL_NEW) in norm(text), 'actual independent RX locals differ'
        assert norm(module.RX_CAPTURE_NEW) in norm(text), 'actual per-descriptor RX resets differ'
        for name in names:
            assert norm(method(template, name)) == norm(method(text, name)), 'stale generated ' + name
    start = text.index('struct RTL8125::R15PoolState {')
    end = text.index('\n};', start) + 3
    harness = PREFIX + '\n' + text[start:end] + '\n'
    harness += '\n\n'.join(method(text, name) for name in names) + '\n' + SUFFIX
    if args.emit:
        print(harness)
        return
    compiler = shlex.split(os.environ['CXX']) if os.environ.get('CXX') else [shutil.which('clang++') or shutil.which('g++') or '']
    if not compiler[0]:
        raise SystemExit('CXX, clang++, or g++ is required for the actual RX-method check')
    with tempfile.TemporaryDirectory(prefix='r27-rx-driver-') as work:
        source, binary = Path(work) / 'rx.cpp', Path(work) / 'rx'
        source.write_text(harness)
        subprocess.run(compiler + ['-std=c++17', '-Wall', '-Wextra',
            '-I', str(ROOT / 'tools/lucy-obs'), str(source), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
    if args.source:
        print('R34 actual generated RX call sites and retained RX4 methods: PASS')


if __name__ == '__main__':
    main()
