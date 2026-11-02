#!/usr/bin/env python3
"""Compile the ACTUAL generated round20 TX methods with IOKit plumbing stubs.

No model of the driver is used: `driver-template.py` is the same text that
`apply-lucy-obs2.py --tx 20` substitutes into RTL812xLucy.cpp, and
`test-native-main.inc` drives it. Run on the Mac:

    python3 tools/r20/test-driver.py
    python3 tools/r20/test-driver.py --source ~/.../RTL812xLucy.cpp   # + layout
    python3 tools/r20/test-driver.py --emit out.cpp                   # Windows

Round 20 adds: the paired complete() on both pre-publish multi-range exits,
kCover for ordinary packets, and the blocked-ring record.
"""
import argparse
from pathlib import Path
import runpy
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
T = runpy.run_path(str(ROOT / 'tools/r20/driver-template.py'))

PREFIX = r'''
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <cstdio>
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
static UInt64 ticks=100; static UInt64 mach_absolute_time(){return ++ticks;}
struct Mbuf {UInt32 token=7,req=1,len=74; UInt32 pkthdr=0; UInt64 pa=0x35e41000ULL;
 Mbuf *next=nullptr; unsigned frees=0; UInt64 freedAt=0;};
using mbuf_t=Mbuf*;
/* pkthdr_len is the WHOLE chain (0 = single mbuf, use len). */
static UInt32 mbuf_pkthdr_len(mbuf_t m){return m->pkthdr ? m->pkthdr : m->len;}
static UInt32 mbuf_len(mbuf_t m){return m->len;}
static void *mbuf_data(mbuf_t m){return (void *)(uintptr_t)m->pa;}
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
    IOMemoryDescriptor *md=nullptr; bool active=false; UInt64 iova=0, len=0;
    static IODMACommand *withSpecification(int, UInt8, UInt64, int, UInt64,
                                           UInt32, IOMapper*, void*)
    { if (stdCmdAllocFails) return nullptr;
      stdCmdCreated++; return new IODMACommand; }
    IOReturn setMemoryDescriptor(IOMemoryDescriptor *d, bool)
    {
        stdPrepareCalls++; md = d; len = d->total();
        if (stdMode == kStdRefuseNoHandle) return kIOReturnIOError;
        /* The real mapper returns mapAddress = IOVA window + in-page offset,
         * i.e. never the physical address. */
        iova = 0x1000000000ULL + (md->ranges[0].va & 4095ULL);
        stdLastHandle = ++stdHandleSeq;      /* mapper published a mapping */
        stdRecordSeq++;
        if (stdMode == kStdRefuseWithHandle) return kIOReturnIOError;
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
        UInt32 cnt = 0; UInt64 slot = 0;
        for (UInt32 i = 0; i < md->n && cnt < *n; i++) {
            segs[cnt].fIOVMAddr = 0x1000000000ULL + slot + (md->ranges[i].va & 4095ULL);
            segs[cnt].fLength = md->ranges[i].len;
            slot += (((md->ranges[i].va & 4095ULL) + md->ranges[i].len + 4095ULL) & ~4095ULL);
            cnt++;
        }
        *n = cnt; return 0;
    }
    /* IODMACommand::complete() is the ONLY unmap entry point in standard mode. */
    IOReturn complete(bool, bool)
    { if (!active) return kIOReturnNotReady; active=false; stdUnmapCount++;
      return stdUnmapFails ? kIOReturnIOError : kIOReturnSuccess; }
    void clearMemoryDescriptor(){ md=nullptr; }
    void release(){ stdCmdReleased++; delete this; }
};

static UInt32 harvestHeldPolling = 0;
class RTL8125 {public:
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
 *t=m->token; *r=m->req; *f=0; return 1;}
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
    if a.source:
        cpp = Path(a.source).read_text()
        g['select_tx']('18')
        output = cpp[cpp.index('IOReturn RTL8125::outputStart('):
                     cpp.index('void RTL8125::txInterrupt()')]
        assert output.index('getPhysicalSegmentsWithCoalesce') < \
            output.index('r17TxMap(m,') < output.index('OSAddAtomic(-numSegs') < \
            output.index('firstDesc->opts1 |= DescOwn') < \
            output.index('r17TxPosted(m)')
        assert 'r17TxComplete(txDirtyDescIndex);' in cpp
        assert 'page-aligned-real-tx-staging' not in cpp
        assert g['body_is_current'](cpp) == (True, None)
    code = (PREFIX + T['MEMBERS'] + TEST_HEAD + T['METHODS'] +
            (ROOT / 'tools/r20/test-native-main.inc').read_text())
    if a.emit:
        Path(a.emit).write_text(code)
        return
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / 'test.cpp'
        src.write_text(code)
        exe = Path(tmp) / 'test'
        subprocess.run(['clang++', '-std=c++17', '-fsanitize=address,undefined',
                        '-I', str(ROOT / 'tools/lucy-obs'),
                        str(src), '-o', str(exe)], check=True)
        import os
        env = dict(os.environ, ASAN_OPTIONS='detect_leaks=0')
        subprocess.run([str(exe)], check=True, env=env)


if __name__ == '__main__':
    main()
