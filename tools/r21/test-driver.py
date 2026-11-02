#!/usr/bin/env python3
"""Compile the ACTUAL generated round20 TX methods with IOKit plumbing stubs.

No model of the driver is used: `driver-template.py` is the same text that
`apply-lucy-obs2.py --tx 20` substitutes into RTL812xLucy.cpp, and
`test-native-main.inc` drives it. Run on the Mac:

    python3 tools/r21/test-driver.py
    python3 tools/r21/test-driver.py --source ~/.../RTL812xLucy.cpp   # + layout
    python3 tools/r21/test-driver.py --emit out.cpp                   # Windows

Round 21 adds: the translation window gate (kQuiesce/kResume), the forced\nwindow-edge ring sample, and the two-phase coverIdentity that cannot leave a\npartially published branch behind. Round 20 added: the paired complete() on both pre-publish multi-range exits,
kCover for ordinary packets, and the blocked-ring record.
"""
import argparse
from pathlib import Path
import runpy
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
T = runpy.run_path(str(ROOT / 'tools/r21/driver-template.py'))

PREFIX = r'''
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <cstdio>
#include <functional>
#include <map>
struct TestNetif {
    unsigned signals = 0;
    std::function<void()> output;
    void signalOutputThread() { signals++; if (output) output(); }
};
using UInt32=uint32_t; using UInt64=uint64_t; using SInt32=int32_t; using UInt8=uint8_t;
using IOReturn=int;
enum {kIOReturnSuccess=0,kIOReturnBadArgument=1,kIOReturnNoMemory=2,
 kIOReturnNoResources=3,kIOReturnBusy=4,kIOReturnNotReady=5,kIOReturnIOError=6};
enum {kIODirectionOut=1};
enum {kMapped=0};
enum {kIODMACommandOutputHost64=0};
enum {kIOMemoryMapperNone=0};
enum {__POLLING=5};
typedef UInt64 IOPhysicalAddress; typedef UInt64 IOPhysicalLength;
/* --- bit helpers: the same protocol the real driver uses from linux/bitops.h --- */
static inline int mock_test_and_set_bit(int nr, volatile UInt32 *a)
{ UInt32 m = 1u << nr; int was = (*a & m) != 0; *a |= m; return was; }
static inline void mock_clear_bit(int nr, volatile UInt32 *a) { *a &= ~(1u << nr); }
static inline int mock_test_bit(int nr, volatile UInt32 *a) { return (int)((*a >> nr) & 1u); }
#define test_and_set_bit(nr,addr) mock_test_and_set_bit((nr),(addr))
#define clear_bit(nr,addr)        mock_clear_bit((nr),(addr))
#define test_bit(nr,addr)         mock_test_bit((nr),(addr))

struct OSObject { virtual ~OSObject() {} virtual void release() { delete this; } };
struct OSNumber : OSObject { UInt64 v = 0; UInt64 unsigned64BitValue() const { return v; } };
#define OSDynamicCast(T,p) ((T*)(p))

/* The probe publishes the generation handle it just created; the driver reads
 * it back through its owner. In this harness the stub command "publishes" it. */
static UInt32 stdLastHandle = 0;
static UInt32 stdHandleSeq = 0;
static UInt32 stdRecordSeq = 0;

/* The probe publishes [63:32]=records [31:0]=handle; the driver compares the
 * record half across prepare(). */
struct IOService { int refs=1; void retain(){refs++;} void release(){refs--;}
  OSObject *copyProperty(const char *){ OSNumber *n = new OSNumber;
    n->v = ((UInt64)stdRecordSeq << 32) | (UInt64)stdLastHandle; return n; } };

#include "RTL812xTxMapNative.hpp"
#include "RTL812xTxMapStd.hpp"
/* Round23: the harness checks the real window geometry (kBase, kSlots,
 * kPagesPerSlot), so it compiles the SAME header the backend uses instead of
 * restating the numbers. */
#include "amd_iommu_tx_core.hpp"
static UInt64 ticks=100; static UInt64 mach_absolute_time(){return ++ticks;}
struct Mbuf {UInt32 token=7,req=1,len=74; UInt32 pkthdr=0; UInt64 pa=0x35e41000ULL;
 bool parsed=true;
 Mbuf *next=nullptr; unsigned frees=0; UInt64 freedAt=0;};
using mbuf_t=Mbuf*;
/* pkthdr_len is the WHOLE chain (0 = single mbuf, use len). */
static UInt32 mbuf_pkthdr_len(mbuf_t m){return m->pkthdr ? m->pkthdr : m->len;}
/* Round22: these two counters are the mechanical proof that the sampler does
 * not dereference an mbuf. r17TxSample must leave them unchanged. */
static int mbufLenCalls = 0, mbufDataCalls = 0;
static UInt32 mbuf_len(mbuf_t m){ mbufLenCalls++; return m->len; }
static void *mbuf_data(mbuf_t m){ mbufDataCalls++; return (void *)(uintptr_t)m->pa; }
static mbuf_t mbuf_next(mbuf_t m){return m->next;}
static UInt64 OSSwapLittleToHostInt64(UInt64 x){return x;}
static UInt32 OSSwapLittleToHostInt32(UInt32 x){return x;}
struct IOPhysicalSegment {UInt64 location,length;};
struct RtlTxDesc {UInt64 addr; UInt32 opts1,opts2;};
static const UInt32 kTxDescMask=1023,kObsPktParsed=1;
static const UInt32 kTxDescSize = 1024 * 32;
static const UInt32 kTxLastDesc = 1023;
#define DescOwn   0x80000000u
#define FirstFrag 0x10000000u
#define LastFrag  0x20000000u
#define RingEnd   0x40000000u
struct IOTimerEventSource {using Action=int; int armed=0;
 static IOTimerEventSource* timerEventSource(void*,int){return new IOTimerEventSource;}
 void release(){delete this;} void setTimeoutMS(int){armed++;} void cancelTimeout(){} };
struct Workloop {int addEventSource(void*){return 0;} void removeEventSource(void*){}};
struct Pci {UInt32 getBusNumber(){return 0x25;} UInt32 getDeviceNumber(){return 0;}
 UInt32 getFunctionNumber(){return 0;}};
struct OSData {static OSData* withBytes(const void*,size_t){return new OSData;}
 void release(){delete this;}};
static void *IOMalloc(size_t n){return calloc(1,n);}
static void IOFree(void*p,size_t){free(p);}
#define IOLog(...) ((void)0)
#define OSMemberFunctionCast(type,obj,method) 0

/* ---------------- standard-object stubs ---------------- */
struct IOMapper { virtual ~IOMapper() {} };
enum {kStdOk=0, kStdRefuseNoHandle=1, kStdRefuseWithHandle=2,
      kStdTwoSegments=3, kStdIdentity=4, kStdTooMany=5};
static int stdMode = kStdOk;          /* what the stub command does */
static int stdUnmapCount = 0;
static int stdUnmapFails = 0;
static int stdCompleteCalls = 0, stdAckCalls = 0;
static std::map<UInt64, UInt64> stdConfirmedRetires;
static int stdPrepareCalls = 0;
static int stdMdCreated = 0, stdMdReleased = 0;
static int stdMdPrepared = 0, stdMdCompleted = 0;
static int stdCmdCreated = 0, stdCmdReleased = 0;
static int stdCmdAllocFails = 0;
static void *kernel_task = nullptr;   /* the real one is opaque; unused here */
struct IOAddressRange { UInt64 address, length; };
using IOVirtualAddress=UInt64; using IOByteCount=UInt32;

struct IOMemoryDescriptor {
    /* Round19 stub: one descriptor, N ranges (the chain). The walk answers per
     * logical offset, exactly what a real IOGeneralMemoryDescriptor does. */
    struct Range { UInt64 va, len; };
    Range ranges[8] = {}; UInt32 n = 0;
    static IOMemoryDescriptor *withAddress(void *a, UInt32 n, int)
    { IOMemoryDescriptor *d = new IOMemoryDescriptor;
      d->ranges[0] = {(UInt64)(uintptr_t)a, n}; d->n = 1; stdMdCreated++; return d; }
    static IOMemoryDescriptor *withAddressRanges(IOAddressRange *r, UInt32 n,
                                                 int, void *)
    { IOMemoryDescriptor *d = new IOMemoryDescriptor;
      for (UInt32 i = 0; i < n && i < 8; i++)
          d->ranges[i] = {r[i].address, r[i].length};
      d->n = n; stdMdCreated++; return d; }
    /* Only the multi-range path wires explicitly (single-range withAddress
     * carries the kernel-private auto-prepare flag). */
    IOReturn prepare(int){ stdMdPrepared++; return 0; }
    IOReturn complete(int){ stdMdCompleted++; return 0; }
    UInt64 total() const { UInt64 s = 0; for (UInt32 i = 0; i < n; i++) s += ranges[i].len; return s; }
    IOPhysicalAddress getPhysicalSegment(UInt64 off, IOPhysicalLength *plen, int)
    { for (UInt32 i = 0; i < n; i++) {
          if (off < ranges[i].len) {
              if (plen) *plen = ranges[i].len - off;
              return ranges[i].va + off;
          }
          off -= ranges[i].len;
      }
      if (plen) *plen = 0; return 0; }
    void release(){ stdMdReleased++; delete this; }
};
struct IODMACommand {
    struct Segment64 {UInt64 fIOVMAddr, fLength;};
    enum { kMapped = 0 };
    IOMemoryDescriptor *md=nullptr; bool active=false; UInt64 iova=0, len=0, handle=0;
    /* Round23: the stub backend hands out one FIXED STRIPE per live mapping,
     * exactly like the real one (amdtx::plan uses `slot`). Round 22 gave every
     * mapping the same window base, which is indistinguishable from an overlap
     * bug -- so it could not have caught one. */
    static UInt32 stubStripe;      /* next stripe to hand out */
    static UInt32 stubLive;        /* bitmask of stripes in use by this stub */
    UInt32 slot = 0;
    static IODMACommand *withSpecification(int, UInt8, UInt64, int, UInt64,
                                           UInt32, IOMapper*, void*)
    { if (stdCmdAllocFails) return nullptr;
      stdCmdCreated++; return new IODMACommand; }
    IOReturn setMemoryDescriptor(IOMemoryDescriptor *d, bool)
    {
        stdPrepareCalls++; md = d; len = d->total();
        if (stdMode == kStdRefuseNoHandle) return kIOReturnIOError;
        /* take the lowest free stripe, as the backend's slot allocator does */
        slot = amdtx::kSlots;
        for (UInt32 k = 0; k < amdtx::kSlots; k++)
            if (!(stubLive & (1u << k))) { slot = k; break; }
        stdLastHandle = ++stdHandleSeq;      /* mapper published a mapping */
        handle = stdLastHandle;
        stdRecordSeq++;
        /* A REFUSED prepare never becomes a live mapping, so it must not claim
         * a stripe. The published-handle refusal is the pinned case: the driver
         * keeps it and its stripe legitimately. */
        if (stdMode == kStdRefuseWithHandle) return kIOReturnIOError;
        stubLive |= (1u << slot);
        /* The real mapper returns window base + stripe offset + in-page offset;
         * never the physical address. */
        iova = amdtx::kBase + (UInt64)slot * amdtx::kPagesPerSlot * 4096ULL +
               (md->ranges[0].va & 4095ULL);
        active = true; return kIOReturnSuccess;
    }
    /* Round19 stub: one run per descriptor range, page-aligned slots exactly
     * like the real mapper's window, so a chain answers with several runs. */
    IOReturn gen64IOVMSegments(UInt64 *, Segment64 *segs, UInt32 *n)
    {
        if (stdMode == kStdIdentity) { segs[0].fIOVMAddr = md->ranges[0].va; segs[0].fLength = len; *n = 1; return 0; }
        /* Capacity case: the command answers within its buffer but its runs do
         * NOT cover the frame (a real command can also refuse to express the
         * layout). The driver must roll the published map back. */
        if (stdMode == kStdTooMany) { for (UInt32 i = 0; i < 4 && i < *n; i++) { segs[i].fIOVMAddr = iova + 0x1000ULL * i; segs[i].fLength = 1; } *n = 4; return 0; }
        /* run i = window_base + slot_i + align_i, with slot_0 = 0. `iova` is
         * window_base + align_0, so the window base is recovered by subtracting
         * that one offset -- computing every run from `iova` plus a span that
         * already contains align_0 double-counts it. */
        const UInt64 wbase = iova - (md->ranges[0].va & 4095ULL);
        UInt32 cnt = 0; UInt64 slot = 0;
        for (UInt32 i = 0; i < md->n && cnt < *n; i++) {
            const UInt64 align = md->ranges[i].va & 4095ULL;
            segs[cnt].fIOVMAddr = wbase + slot + align;
            segs[cnt].fLength = md->ranges[i].len;
            slot += ((align + md->ranges[i].len + 4095ULL) & ~4095ULL);
            cnt++;
        }
        *n = cnt; return 0;
    }
    /* IODMACommand::complete() is the ONLY unmap entry point in standard mode. */
    IOReturn complete(bool, bool)
    { stdCompleteCalls++;
      if (!active) return kIOReturnNotReady; active=false; stdUnmapCount++;
      if (!stdUnmapFails) {
          stubLive &= ~(1u << slot);
          stdConfirmedRetires[handle] = mach_absolute_time();
      }
      return stdUnmapFails ? kIOReturnIOError : kIOReturnSuccess; }
    IOReturn clearMemoryDescriptor(bool autoComplete=true)
    { if (autoComplete && active) complete(true, false);
      md=nullptr; return kIOReturnSuccess; }
    void release(){ stdCmdReleased++; delete this; }
};

static UInt32 harvestHeldPolling = 0;
/* Round23: the stub backend's stripe bookkeeping (see IODMACommand above). */
UInt32 IODMACommand::stubLive = 0;
class RTL8125 {public:
 TestNetif interface; TestNetif *netif = &interface;
 bool enableTSO4=false, enableTSO6=false;
 bool useAppleVTD=false; Workloop wl; Workloop *workLoop=&wl; Pci pci; Pci*pciDevice=&pci;
 UInt32 txNextDescIndex=1000, txTailPtr0=1000, txClosePtr0=1003;
 UInt32 txDirtyDescIndex=1000, txDescDoneCount=0; SInt32 txNumFreeDesc=24;
 UInt64 txPhyAddr=0x3ff00000ULL;
 volatile UInt32 stateFlags=0;
 struct {UInt32 MaxTxDescPtrMask=65535;} linuxData;
 RtlTxDesc txDescArray[1024]{};
 mbuf_t txMbufArray[1024]{};
 UInt32 txInterruptCalls=0; int inHarvest=0;
 /* The template harvests from the retire timer. This records that it did so
  * while holding the driver's own exclusion, which is the round-18 correction. */
 void txInterrupt(){ assert(!inHarvest); inHarvest=1; txInterruptCalls++;
   harvestHeldPolling = (UInt32)test_bit(__POLLING,&stateFlags); inHarvest=0; }
 /* The kernel's freePacket frees the WHOLE chain; the stub does the same so a
  * leaked tail cannot hide behind a freed head. */
 void freePacket(mbuf_t m){ for (mbuf_t c = m; c; c = c->next) {
     assert(!c->frees); c->frees++; c->freedAt = mach_absolute_time(); } }
 UInt32 obsParseBiz(mbuf_t m,UInt32,bool,UInt32*t,UInt32*r,UInt32*f){
 *t=m->token; *r=m->req; *f=0; return m->parsed ? kObsPktParsed : 0;}
 void setProperty(const char*,OSData*){}
 void setProperty(const char*,const char*){}
 void setProperty(const char*,UInt64,int){}
'''

TEST_HEAD = '\n};\n'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--emit')
    ap.add_argument('--source')
    a = ap.parse_args()
    # Structural checks against the real generator, not against a copy of it.
    g = runpy.run_path(str(ROOT / 'tools/apply-lucy-obs2.py'))
    assert 'r17TxMap' not in g['OUTPUT_FILL_NEW']  # never after OWN stores
    tx18 = g['select_tx']('18')
    g['select_tx']('16')                            # selection must be reversible
    g['select_tx']('17')
    assert tx18['HOOKS'][0].startswith('if (!r17TxMap(')
    # Exercise the real patch function, including the pre-dequeue hook. The
    # fixture supplies its exact anchors; methods are the actual template text.
    fixture = ('        r15Pool = NULL;\n'
               'void RTL8125::stop(IOService *provider) {\n    if (workLoop) {}\n}\n'
               'IOReturn RTL8125::outputStart() {\n'
               'while ((interface->dequeueOutputPackets(1, &m, NULL, NULL, NULL) == kIOReturnSuccess)) {\n'
               '        OSAddAtomic(-numSegs, &txNumFreeDesc);\n'
               '                txMbufArray[index] = m;\n'
               '        firstDesc->opts1 |= DescOwn;\n}\n'
               '    result = (txNumFreeDesc > (kMaxSegs + 3)) ? kIOReturnSuccess : kIOReturnNoResources;\n}\n'
               '        m = txMbufArray[txDirtyDescIndex];\n'
               '    if (!functionName || !functionName->isEqualTo(r15pool::kFunctionName)) {}\n'
               + T['METHODS'])
    patched = T['patch_cpp'](fixture)
    for hook in T['HOOKS']:
        assert hook in patched, hook
    assert 'r17TxOutputReady() && interface->dequeueOutputPackets(' in patched
    assert patched.index('r17TxOutputReady() && interface->dequeue') < patched.index('r17TxMap(m, txSegments')
    tail_result = 'result = (r17TxOutputReady() && (txNumFreeDesc > (kMaxSegs + 3))) ? kIOReturnSuccess : kIOReturnNoResources;'
    assert tail_result in patched
    assert patched.index(tail_result) > patched.index('r17TxPosted(m);')
    if a.source:
        cpp = Path(a.source).read_text()
        g['select_tx']('21')  # this harness exercises the r21 generator, not r18
        # The TX module is unchanged when Round27 adds its separate RX pool.
        # Select that real pool before comparing the complete generated body.
        if 'bool RTL8125::r27RxActive()' in cpp:
            g['select_rx']('27')
        output = cpp[cpp.index('IOReturn RTL8125::outputStart('):
                     cpp.index('void RTL8125::txInterrupt()')]
        assert output.index('getPhysicalSegmentsWithCoalesce') < \
            output.index('r17TxMap(m,') < output.index('OSAddAtomic(-numSegs') < \
            output.index('firstDesc->opts1 |= DescOwn') < \
            output.index('r17TxPosted(m)')
        assert output.index('r17TxOutputReady() && interface->dequeue') < output.index('r17TxMap(m,')
        assert tail_result in output
        assert output.index(tail_result) > output.index('r17TxPosted(m)')
        assert output.count('r17TxMap(m,') == 1
        assert 'r17TxComplete(txDirtyDescIndex);' in cpp
        assert 'page-aligned-real-tx-staging' not in cpp
        current = g['body_is_current'](cpp)
        assert current == (True, None), current
    code = (PREFIX + T['MEMBERS'] + TEST_HEAD + T['METHODS'] +
            (ROOT / 'tools/r21/test-native-main.inc').read_text())
    if a.emit:
        Path(a.emit).write_text(code)
        return
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / 'test.cpp'
        src.write_text(code)
        exe = Path(tmp) / 'test'
        subprocess.run(['clang++', '-std=c++17', '-fsanitize=address,undefined',
                        '-I', str(ROOT / 'tools/lucy-obs'),
                        '-I', str(ROOT / 'kext'),
                        str(src), '-o', str(exe)], check=True)
        import os
        env = dict(os.environ, ASAN_OPTIONS='detect_leaks=0')
        subprocess.run([str(exe)], check=True, env=env)


if __name__ == '__main__':
    main()
