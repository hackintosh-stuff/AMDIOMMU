#!/usr/bin/env python3
"""Focused host regression: compile ACTUAL generated round15 driver methods.

No hardware, remote access, full gate suite, or substitute state-machine model.
Only mbuf/clock/IOKit allocation plumbing is stubbed. Default runs a local C++
compiler; --emit PATH writes the standalone generated test for another compiler.
--check-extraction validates source-hook wiring without requiring a compiler.
--mainline checks normal full-pool Prepare, open-ended authorization, and Disarm.
"""
import argparse
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def extract(text, signature):
    start = text.index(signature)
    brace = text.index('{', start)
    depth = 0
    for end in range(brace, len(text)):
        if text[end] == '{':
            depth += 1
        elif text[end] == '}':
            depth -= 1
            if depth == 0:
                return text[start:end + 1]
    raise AssertionError('unclosed actual function: ' + signature)


PREFIX = r'''
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>
#include "RTL812xRxPool.hpp"
#include "RTL812xRxMap.hpp"
using UInt8 = unsigned char;
using UInt32 = unsigned int;
using UInt64 = unsigned long long;
#include "RTL812xObsLog.hpp"
using IOReturn = int;
static const int kIOReturnSuccess=0, kIOReturnBadArgument=1,
    kIOReturnNotReady=2, kIOReturnNoMemory=3, kIOReturnNotAligned=4,
    kIOReturnUnsupported=5, kIOReturnBusy=6;
static const UInt32 PAGE_SIZE=4096, kRxBufferSize=4096, kNumTxDesc=1024;
static const UInt32 RxRES=1u<<21;
static const int MBUF_DONTWAIT=0;
enum { __ENABLED=0, __LINK_UP=1, __POLLING=2 };
static UInt64 nowTicks=1000, nextAllocation=0x400000000ULL;
static unsigned allocations=0;
static UInt64 mach_absolute_time() { return nowTicks; }
static void nanoseconds_to_absolutetime(UInt64 n, UInt64 *out) { *out=n; }
static UInt64 OSSwapLittleToHostInt64(UInt64 x) { return x; }
static void *IOMallocZero(size_t n) { return std::calloc(1,n); }
static void IOFree(void *p, size_t) { std::free(p); }
static bool test_bit(int b, const UInt32 *p) { return (*p & (1u<<b))!=0; }
static bool test_and_set_bit(int b, UInt32 *p) {
    bool old=test_bit(b,p); *p |= 1u<<b; return old;
}
static void clear_bit(int b, UInt32 *p) { *p &= ~(1u<<b); }
struct Mbuf {
    alignas(4096) UInt8 data[4096];
    UInt64 pa;
    UInt32 capacity=4096, length=0, freed=0;
    bool breakLast=false;
    Mbuf *next=nullptr;
    UInt8 *external=nullptr;
    void (*extfree)(char*,unsigned,char*)=nullptr;
    unsigned callbackCount=0;
};
using mbuf_t = Mbuf*;
static std::vector<mbuf_t> allMbufs;
static mbuf_t makeMbuf(UInt64 pa) {
    mbuf_t m=new Mbuf{}; m->pa=pa; allMbufs.push_back(m); return m;
}
using IOByteCount = size_t;
using caddr_t = char*;
using u_int = unsigned;
static const void *kernel_task=nullptr;
static const unsigned kIODirectionInOut=3, kIOMemoryMapperNone=0x800;
static const int MBUF_TYPE_DATA=1;
static int physicalFailureMode=0;
static UInt64 nextPhysicalAllocation=0x600000000ULL;
static UInt64 nextLowPhysicalAllocation=0x100000000ULL;
class IOBufferMemoryDescriptor;
static std::vector<IOBufferMemoryDescriptor*> allRegions;
class IOBufferMemoryDescriptor {
public:
    alignas(4096) UInt8 bytes[4096];
    UInt64 pa;
    bool prepared=false;
    unsigned completeCount=0, releaseCount=0;
    mbuf_t wrapper=nullptr;
    static IOBufferMemoryDescriptor *inTaskWithOptions(const void *,unsigned options,
                                                       UInt32 size,UInt32 alignment) {
        assert(options==(kIODirectionInOut|kIOMemoryMapperNone));
        assert(size==4096 && alignment==4096);
        if (physicalFailureMode==1) return nullptr;
        auto *r=new IOBufferMemoryDescriptor{};
        if (physicalFailureMode==6) { r->pa=nextLowPhysicalAllocation; nextLowPhysicalAllocation+=4096; }
        else { r->pa=nextPhysicalAllocation; nextPhysicalAllocation+=4096; }
        allRegions.push_back(r); return r;
    }
    int prepare() { if (physicalFailureMode==2) return 1; prepared=true; return 0; }
    int complete() {
        assert(prepared && completeCount==0);
        if (wrapper) assert(wrapper->freed==1 && wrapper->callbackCount==1);
        ++completeCount; return 0;
    }
    void release() {
        assert(releaseCount==0 && (!prepared || completeCount==1)); ++releaseCount;
    }
    void *getBytesNoCopy() { return bytes; }
    UInt32 getLength() { return 4096; }
    UInt64 getPhysicalSegment(unsigned offset,IOByteCount *span,unsigned options) {
        assert(offset==0 && options==kIOMemoryMapperNone);
        *span=(physicalFailureMode==5)?1024:4096; return pa;
    }
};
static mbuf_t mbuf_next(mbuf_t m) { return m->next; }
static void *mbuf_datastart(mbuf_t m) { return m->external?m->external:m->data; }
static void *mbuf_data(mbuf_t m) { return mbuf_datastart(m); }
static UInt32 mbuf_maxlen(mbuf_t m) { return m->capacity; }
static UInt32 mbuf_trailingspace(mbuf_t m) { return m->capacity-m->length; }
static UInt64 mbuf_data_to_physical(void *p) {
    uintptr_t v=(uintptr_t)p;
    for (auto *r:allRegions) {
        uintptr_t base=(uintptr_t)r->bytes;
        assert(!(v>=base && v<base+4096)); // external VM MUST NOT use this API
    }
    for (mbuf_t m:allMbufs) {
        uintptr_t base=(uintptr_t)m->data;
        if (v>=base && v<base+4096) {
            UInt64 off=v-base;
            return m->pa+off+((m->breakLast && off==4095)?4096:0);
        }
    }
    return 0;
}
static void mbuf_freem_list(mbuf_t m) {
    for (;m;m=m->next) {
        assert(m->freed==0);
        if (m->external) {
            assert(m->extfree);
            for (auto *r:allRegions) if (r->bytes==m->external)
                assert(r->prepared && r->completeCount==0 && r->releaseCount==0);
            m->extfree((char*)m->external,4096,nullptr); ++m->callbackCount;
        }
        ++m->freed;
    }
}
static int mbuf_gethdr(int,int,mbuf_t *out) {
    if (physicalFailureMode==3) { *out=nullptr; return 1; }
    *out=makeMbuf(0); (*out)->capacity=256; return 0;
}
static int mbuf_attachcluster(int,int,mbuf_t *m,char *bytes,
    void (*callback)(char*,unsigned,char*),size_t size,char *context) {
    assert(*m && size==4096 && context==nullptr && callback);
    if (physicalFailureMode==4) { mbuf_freem_list(*m); *m=nullptr; return 1; }
    (*m)->external=(UInt8*)bytes; (*m)->capacity=4096; (*m)->extfree=callback;
    for (auto *r:allRegions) if (r->bytes==(UInt8*)bytes) r->wrapper=*m;
    return 0;
}
static int mbuf_allocpacket(int, UInt32 size, unsigned *chunks, mbuf_t *out) {
    assert(size==4096 && *chunks==1); ++allocations;
    *out=makeMbuf(nextAllocation); nextAllocation+=4096; return 0;
}
static void mbuf_setdata(mbuf_t m, void *p, UInt32 len) {
    assert(p==mbuf_datastart(m)); m->length=len;
}
static void mbuf_copy_pkthdr(mbuf_t, mbuf_t) {}
static void mbuf_pkthdr_setheader(mbuf_t, void *) {}
#define bcopy(a,b,n) std::memmove((b),(a),(n))
struct OSObject {};
struct Desc { struct { UInt64 addr, blen; } buf; };
struct Buffer { mbuf_t mbuf; UInt64 phyAddr; };
struct RxPoolStub {
    mbuf_t delivery=nullptr;
    mbuf_t getPacket(UInt32, int) { mbuf_t m=delivery; delivery=nullptr; return m; }
};
struct PostHdr { UInt32 ringGen=7; };
class RTL8125: public OSObject {
public:
    struct R15PoolState;
    R15PoolState *r15Pool=nullptr;
    Buffer *rxBufArray=nullptr;
    Desc *rxDescArray=nullptr;
    RxPoolStub *rxPool=nullptr;
    PostHdr *rxpostHdr=nullptr;
    void *netif=(void*)1;
    UInt32 stateFlags=(1u<<__ENABLED)|(1u<<__LINK_UP);
    UInt32 mtu=1500, obsEpoch=123;
    bool useAppleVTD=false;
    const char *scope=nullptr;
    bool setProperty(const char *key,const char *value) {
        if (std::strcmp(key,"rtl812x-r15-obs-scope")==0) scope=value;
        return true;
    }
    bool setProperty(const char *,UInt64,unsigned) { return true; }
    bool r15PoolObserve(UInt32,UInt32,UInt32);
    static IOReturn r15PoolAction(OSObject*,void*,void*,void*,void*);
    IOReturn r15PoolControl(r15pool::Request*);
    mbuf_t r15PoolCopy(mbuf_t,UInt32);
    void r15PoolRearm(UInt32,UInt64,UInt32,UInt32,UInt32,UInt32,UInt64*);
    void r15PoolPosted(UInt32,UInt64);
    void r15PoolInvalidate();
    void r15PoolFree();
    // Cyclic RX methods are covered by their own real-method harness. This
    // allocator/authorization case does not install any DMA bindings.
    void r27RxRearm(UInt32,UInt64,UInt32,UInt32,UInt32,UInt32,UInt64*) { assert(false); }
    void r27RxPosted(UInt32,UInt64) { assert(false); }
};
'''

TESTS = r'''
static void initialize(RTL8125 &d, RxPoolStub &pool, PostHdr &hdr) {
    d.rxPool=&pool; d.rxpostHdr=&hdr;
    d.rxBufArray=new Buffer[r15pool::kRingCount]{};
    d.rxDescArray=new Desc[r15pool::kRingCount]{};
    for (UInt32 i=0;i<r15pool::kRingCount;i++) {
        UInt64 pa=0x200000000ULL+(UInt64)i*4096;
        d.rxBufArray[i].mbuf=makeMbuf(pa);
        d.rxBufArray[i].phyAddr=pa;
        d.rxDescArray[i].buf.addr=pa;
    }
}
static IOReturn act(RTL8125 &d,r15pool::Request *r) {
    return RTL8125::r15PoolAction(&d,r,nullptr,nullptr,nullptr);
}
int main() {
    static_assert(sizeof(r15pool::Request)==114856,"actual shared ABI size");
    mbuf_t span=makeMbuf(0x700000000ULL); UInt64 pa=0;
    assert(r15PhysicalSpan(span,&pa) && pa==span->pa);
    span->capacity=4095; assert(!r15PhysicalSpan(span,&pa));
    span->capacity=4096; span->breakLast=true;
    assert(!r15PhysicalSpan(span,&pa)); // first byte alone was insufficient
    span->breakLast=false; span->next=span; assert(!r15PhysicalSpan(span,&pa));
    span->next=nullptr;

    RTL8125 d; RxPoolStub pool; PostHdr hdr; initialize(d,pool,hdr);
    auto *r=new r15pool::Request{};
    r->version=r15pool::kVersion; r->bytes=sizeof(*r); r->op=r15pool::kPrepare;
    r->reserved=444; // opt-in declared business token, separate from flood77
    d.useAppleVTD=true;
    assert(act(d,r)==kIOReturnUnsupported && !d.r15Pool && allocations==0);
    d.useAppleVTD=false; d.stateFlags|=1u<<__POLLING;
    assert(act(d,r)==kIOReturnBusy && !d.r15Pool && allocations==0);
    d.stateFlags&=~(1u<<__POLLING);
    assert(act(d,r)==kIOReturnSuccess);
    assert(r->out.state==r15pool::kPrepared && r->out.mtu==1500);
    assert(r->out.entryCount==r15pool::kMaxEntries && r->out.spareCount==r15pool::kSpareCount);
    assert(r->out.allocationAttempts==r15pool::kMaxAttempts+r15pool::kExtraIOBufferAttempts && allocations==r15pool::kMaxAttempts);
    assert(d.r15Pool->physicalAttempts==r15pool::kExtraIOBufferAttempts);
    for (unsigned i=1024;i<r15pool::kMaxEntries;i++) {
        assert(r->out.entries[i].reserved==r15pool::kSourceIOBuffer);
        assert(d.r15Pool->regions[i] && d.r15Pool->regions[i]->prepared);
    }
    assert(r->out.highSpareCount==r15pool::kSpareCount);
    assert(r->out.reserved[0]==444 && std::strstr(d.scope,"declared-business-only"));
    assert(d.r15PoolObserve(kObsKindTxDone,10,0)); // prior-pending is retained
    assert(!d.r15PoolObserve(kObsKindTxSubmit,10,77));
    assert(!d.r15PoolObserve(kObsKindTxDone,10,0)); // tokenless done uses slot
    assert(d.r15PoolObserve(kObsKindTxSubmit,11,444));
    assert(d.r15PoolObserve(kObsKindTxDone,11,0));
    assert(!d.r15PoolObserve(kObsKindRxDone,0,77));
    assert(!d.r15PoolObserve(kObsKindTxDoorbell,10,77));
    assert(d.r15PoolObserve(kObsKindRxDone,0,444));
    assert(d.r15PoolObserve(kObsKindTxDoorbell,11,444));
    for (unsigned i=1025;i<r15pool::kMaxEntries;i++)
        assert(r->out.entries[i-1].addr>r->out.entries[i].addr);
    std::vector<r15pool::Entry> immutable(r->out.entries,r->out.entries+r15pool::kMaxEntries);
    mbuf_t original=d.rxBufArray[0].mbuf;
    UInt64 old=original->pa, addr=old;
    d.r15PoolRearm(0,old,128,128,0,0,&addr);
    assert(addr==old && d.r15Pool->snap.replacements==0); // not authorized
    r->poolId=r->out.poolId; r->expectedGeneration=r->out.generation;
    r->op=r15pool::kAuthorize; r->replaceLimit=2;
    r->mapCompletedAt=999; r->deadline=5000;
    assert(act(d,r)==kIOReturnBadArgument); // before Prepare timestamp
    nowTicks=1010; r->mapCompletedAt=1005;
    assert(act(d,r)==kIOReturnSuccess);
    assert(r->out.mapCompletedAt<r->out.tAuthorized);
    assert(r->out.rxCompletions==0 && r->out.reserved[1]==4);
    d.r15PoolRearm(0,old,128,128,0,0,&addr);
    auto &w=d.r15Pool->snap.witnesses[0];
    assert(addr!=old && addr==immutable[1024].addr && w.capacity==4096);
    assert(w.tPost==0 && original->freed==0 && d.rxBufArray[0].mbuf!=original);
    d.rxDescArray[0].buf.addr=addr;
    d.rxDescArray[0].buf.blen=4096ULL|0x80000000ULL;
    nowTicks=1011; d.r15PoolPosted(0,addr);
    assert(w.tPost==1011 && w.tDone==0);
    nowTicks=1020;
    UInt64 newAddr=addr;
    d.r15PoolRearm(0,newAddr,1018,1018,77,10001,&addr);
    assert(w.newAddr==newAddr && w.tDone==1020 && w.token==77 && w.reqId==10001);
    assert(w.flags==r15pool::kWitnessCompleted && w.doneLength==1018);
    assert(w.tDone>w.tPost && d.r15Pool->snap.completions==1);
    d.rxDescArray[0].buf.addr=addr; d.r15PoolPosted(0,addr);
    assert(std::memcmp(immutable.data(),d.r15Pool->snap.entries,
                       immutable.size()*sizeof(immutable[0]))==0);
    assert(d.mtu==1500 && original->freed==0);

    // Delivery is separate owned memory even after swaps and Disarm.
    mbuf_t delivery=makeMbuf(0x800000000ULL);
    mbuf_t current=d.rxBufArray[0].mbuf;
    std::memset(mbuf_data(current),0x5a,128); pool.delivery=delivery;
    assert(d.r15PoolCopy(current,128)==delivery);
    assert(delivery!=current && ((UInt8*)mbuf_data(delivery))[127]==0x5a && current->freed==0);
    UInt64 slot1=d.rxBufArray[1].phyAddr;
    nowTicks=5001; addr=slot1;
    d.r15PoolRearm(1,slot1,128,128,0,0,&addr);
    assert(addr==slot1 && d.r15Pool->snap.state==r15pool::kDisarmed);
    assert(d.r15Pool->snap.flags&r15pool::kFlagExpired);
    r->op=r15pool::kDisarm; assert(act(d,r)==kIOReturnSuccess);
    assert(r->out.replacements==2 && r->out.completions==1);
    assert(d.r15PoolCopy(current,128)==nullptr);
    assert(d.r15Pool->snap.copyFailures==1 && current->freed==0);
    addr=slot1; d.r15PoolRearm(1,slot1,128,128,0,0,&addr);
    assert(addr==slot1); // disarmed copies cannot consume another spare
    UInt32 gen=d.r15Pool->snap.generation;
    d.r15PoolInvalidate();
    assert(d.r15Pool->snap.generation==gen+1);
    assert(d.r15Pool->snap.flags&r15pool::kFlagRingReset);
    r->op=r15pool::kAuthorize; assert(act(d,r)==kIOReturnBadArgument);
    std::vector<mbuf_t> owned(d.r15Pool->mbufs,d.r15Pool->mbufs+r15pool::kMaxEntries);
    for (mbuf_t m:owned) assert(m->freed==0);
    d.r15PoolFree(); assert(!d.r15Pool);
    for (mbuf_t m:owned) assert(m->freed==1);
    for (unsigned i=0;i<1024;i++) assert(!d.rxBufArray[i].mbuf);
    assert(delivery->freed==0); // driver did not free the delivery copy
    delete[] d.rxBufArray; delete[] d.rxDescArray;

    // Real rearm body must fail closed if slot/descriptor/pool association moves.
    RTL8125 d2; initialize(d2,pool,hdr); nowTicks=6000;
    r->op=r15pool::kPrepare; assert(act(d2,r)==kIOReturnSuccess);
    mbuf_t canonical=d2.rxBufArray[3].mbuf;
    mbuf_t foreign=makeMbuf(0x900000000ULL);
    UInt64 a=foreign->pa;
    d2.rxBufArray[3].mbuf=foreign; d2.rxBufArray[3].phyAddr=a;
    d2.rxDescArray[3].buf.addr=a;
    d2.r15PoolRearm(3,a,128,128,0,0,&a);
    assert(d2.r15Pool->snap.flags&r15pool::kFlagAddressMismatch);
    assert(d2.r15Pool->snap.state==r15pool::kDisarmed);
    assert(a==canonical->pa && d2.rxBufArray[3].mbuf==canonical);
    assert(d2.rxBufArray[3].phyAddr==canonical->pa && foreign->freed==0);
    // Even a corrupted out-of-domain id falls back to the owned original slot.
    d2.r15Pool->slotId[4]=0xffffffffu;
    d2.rxBufArray[4].mbuf=foreign; a=foreign->pa;
    d2.r15PoolRearm(4,a,128,128,0,0,&a);
    assert(a==d2.r15Pool->snap.entries[4].addr);
    assert(d2.rxBufArray[4].mbuf==d2.r15Pool->mbufs[4] && foreign->freed==0);
    d2.r15PoolFree(); delete[] d2.rxBufArray; delete[] d2.rxDescArray;
    // Every alternative failure stage and low/rejected candidates fall back
    // to the existing native pool without leaking/freeing ring aliases.
    for (int mode=1;mode<=6;mode++) {
        physicalFailureMode=mode;
        RTL8125 failed; initialize(failed,pool,hdr); nowTicks+=1000;
        r->op=r15pool::kPrepare; assert(act(failed,r)==kIOReturnSuccess);
        assert(failed.r15Pool->physicalAttempts==r15pool::kExtraIOBufferAttempts && r->out.spareCount==r15pool::kSpareCount);
        for (unsigned i=1024;i<r15pool::kMaxEntries;i++) {
            assert(r->out.entries[i].reserved==r15pool::kSourceMbuf);
            assert(!failed.r15Pool->regions[i]);
        }
        unsigned stage=(mode==1)?0:(mode==2)?1:(mode==3||mode==4)?2:3;
        if (mode<=5) assert(failed.r15Pool->physicalFailures[stage]==r15pool::kExtraIOBufferAttempts);
        else for (unsigned i=0;i<4;i++) assert(failed.r15Pool->physicalFailures[i]==0);
        failed.r15PoolFree(); delete[] failed.rxBufArray; delete[] failed.rxDescArray;
    }
    physicalFailureMode=0;
    for (auto *region:allRegions) {
        assert(region->releaseCount==1);
        assert(region->completeCount==(region->prepared?1u:0u));
        if (region->wrapper) assert(region->wrapper->callbackCount==1);
    }
    delete r;
    for (mbuf_t m:allMbufs) delete m;
    for (auto *region:allRegions) delete region;
    std::puts("round15 actual generated pool methods: PASS");
}
'''


MAINLINE_TEST = r'''
int main() {
    static_assert(r15pool::kVersion==2 && r15pool::kSpareCount==1024);
    static_assert(sizeof(r15pool::Request)==114856);
    RTL8125 d; RxPoolStub pool; PostHdr hdr;
    initialize(d,pool,hdr);
    auto *r=new r15pool::Request{};
    r->version=r15pool::kVersion; r->bytes=sizeof(*r);
    r->op=r15pool::kPrepare; r->reserved=0x30abcd;
    assert(act(d,r)==kIOReturnSuccess);
    assert(r->out.state==r15pool::kPrepared && r->out.entryCount==2048);
    assert(r->out.spareCount==1024 && r->out.highSpareCount==1024);
    assert(r->out.allocationAttempts==r15pool::kMaxAttempts+r15pool::kExtraIOBufferAttempts);
    assert(allocations==r15pool::kMaxAttempts);
    for (unsigned i=0;i<r15pool::kMaxEntries;++i) {
        const auto &e=r->out.entries[i];
        assert(e.id==i && e.capacity==4096 && d.r15Pool->mbufs[i]);
        if (i<r15pool::kRingCount) {
            assert(e.kind==r15pool::kEntryRing);
            assert(d.rxBufArray[i].mbuf==d.r15Pool->mbufs[i]);
            assert(d.rxDescArray[i].buf.addr==e.addr);
        } else {
            assert(e.kind==r15pool::kEntrySpare);
            assert(e.reserved==r15pool::kSourceIOBuffer);
            assert(d.r15Pool->regions[i] && d.r15Pool->regions[i]->prepared);
            if (i>r15pool::kRingCount) assert(r->out.entries[i-1].addr>e.addr);
        }
    }
    std::vector<mbuf_t> owned(d.r15Pool->mbufs,d.r15Pool->mbufs+r15pool::kMaxEntries);
    for (mbuf_t m:owned) assert(m->freed==0);
    r->poolId=r->out.poolId; r->expectedGeneration=r->out.generation;
    nowTicks=2000;
    r->op=r15pool::kAuthorize; r->mapCompletedAt=1500;
    r->deadline=0; r->replaceLimit=r15pool::kSpareCount;
    assert(act(d,r)==kIOReturnSuccess);
    assert(r->out.state==r15pool::kAuthorized && !r->out.deadline);
    nowTicks+=125000000000ULL;
    r->op=r15pool::kSnapshot;
    assert(act(d,r)==kIOReturnSuccess);
    assert(r->out.state==r15pool::kAuthorized && !r->out.deadline);
    r->op=r15pool::kDisarm;
    assert(act(d,r)==kIOReturnSuccess && r->out.state==r15pool::kDisarmed);
    d.r15PoolFree(); assert(!d.r15Pool);
    for (mbuf_t m:owned) assert(m->freed==1);
    for (unsigned i=0;i<r15pool::kRingCount;++i) assert(!d.rxBufArray[i].mbuf);
    for (auto *region:allRegions) {
        assert(region->completeCount==1 && region->releaseCount==1);
        assert(region->wrapper && region->wrapper->callbackCount==1);
    }
    delete[] d.rxBufArray; delete[] d.rxDescArray; delete r;
    for (mbuf_t m:allMbufs) delete m;
    for (auto *region:allRegions) delete region;
    std::puts("R31 actual pool Prepare/Authorize(deadline=0)/Disarm/release: 1024 ring + 1024 spares; pool2 ABI PASS");
}
'''


def generate(mainline=False):
    n = runpy.run_path(str(ROOT / 'tools/apply-lucy-obs2.py'))
    if mainline:
        n['select_rx']('32')
        n = n['select_rx'].__globals__
    text = n['POOL_METHODS']
    state = extract(text, 'struct RTL8125::R15PoolState') + ';'
    functions = [extract(text, 'static bool r15PhysicalSpan'),
                 extract(text, 'static void r15ExternalFree'),
                 extract(text, 'static void r15ReleaseOwned')]
    for result, name in (
            ('IOReturn', 'r15PoolAction'), ('IOReturn', 'r15PoolControl'),
            ('mbuf_t', 'r15PoolCopy'), ('void', 'r15PoolRearm'),
            ('void', 'r15PoolPosted'), ('void', 'r15PoolInvalidate'),
            ('void', 'r15PoolFree'), ('bool', 'r15PoolObserve')):
        functions.append(extract(text, result + ' RTL8125::' + name))
    hook = n['RX_NEW']
    assert hook.index('r15PoolRearm(') < hook.index('desc->buf.addr =')
    assert hook.index('desc->buf.addr =') < hook.index('wmb();')
    assert hook.index('wmb();') < hook.index('desc->buf.blen =')
    assert hook.index('desc->buf.blen =') < hook.index('r15PoolPosted(')
    assert 'replaced = false;' in n['POOL_RX_NEW']
    assert 'r15PoolCopy' in n['POOL_RX_NEW']
    obs = extract(n['OBS_METHODS'], 'void RTL8125::obsWrite')
    assert obs.index('r15PoolObserve(') < obs.index('obslog::writeRecord(')
    tests = TESTS[:TESTS.index('int main()')] + MAINLINE_TEST if mainline else TESTS
    return PREFIX + '\n' + state + '\n' + '\n\n'.join(functions) + tests


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--emit', type=Path)
    parser.add_argument('--check-extraction', action='store_true')
    parser.add_argument('--mainline', action='store_true')
    args = parser.parse_args()
    source = generate(args.mainline)
    if args.emit:
        args.emit.write_text(source, encoding='utf-8')
        print('emitted actual driver-body test:', args.emit)
        return 0
    if args.check_extraction:
        print('actual pool-body extraction + address/barrier/OWN/post hook ordering: PASS')
        return 0
    compiler = os.environ.get('CXX') or next(
        (shutil.which(c) for c in ('clang++', 'g++', 'c++') if shutil.which(c)), None)
    if not compiler:
        parser.error('no local C++ compiler; use --emit PATH or --check-extraction')
    with tempfile.TemporaryDirectory(prefix='r15-pool-test-') as directory:
        folder = Path(directory)
        cpp = folder / 'r15-pool-test.cpp'
        exe = folder / ('r15-pool-test.exe' if os.name == 'nt' else 'r15-pool-test')
        cpp.write_text(source, encoding='utf-8')
        subprocess.run([compiler, '-std=c++17', '-O1', '-Wall', '-Wextra',
                        '-I', str(ROOT / 'tools/lucy-obs'), str(cpp),
                        '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
