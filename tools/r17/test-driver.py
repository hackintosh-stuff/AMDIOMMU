#!/usr/bin/env python3
"""Compile the ACTUAL generated round17 TX methods with IOKit plumbing stubs.

No model of the driver is used: `driver-template.py` is the same text that
`apply-lucy-obs2.py --tx 17` substitutes into RTL812xLucy.cpp, and
`test-native-main.inc` drives it. Run on the Mac:

    python3 tools/r17/test-driver.py
    python3 tools/r17/test-driver.py --source ~/.../RTL812xLucy.cpp   # + layout
    python3 tools/r17/test-driver.py --emit out.cpp                   # Windows
"""
import argparse
from pathlib import Path
import runpy
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
T = runpy.run_path(str(ROOT / 'tools/r17/driver-template.py'))

PREFIX = r'''
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <cstdio>
using UInt32=uint32_t; using UInt64=uint64_t; using SInt32=int32_t;
using IOReturn=int;
enum {kIOReturnSuccess=0,kIOReturnBadArgument=1,kIOReturnNoMemory=2,
 kIOReturnNoResources=3,kIOReturnBusy=4,kIOReturnNotReady=5};
struct IOService {int refs=1; void retain(){refs++;} void release(){refs--;}};
#include "RTL812xTxMapNative.hpp"
static UInt64 ticks=100; static UInt64 mach_absolute_time(){return ++ticks;}
struct Mbuf {UInt32 token=7,req=1,len=74; unsigned frees=0; UInt64 freedAt=0;};
using mbuf_t=Mbuf*;
static UInt32 mbuf_pkthdr_len(mbuf_t m){return m->len;}
static UInt64 OSSwapLittleToHostInt64(UInt64 x){return x;}
static UInt32 OSSwapLittleToHostInt32(UInt32 x){return x;}
struct IOPhysicalSegment {UInt64 location,length;};
struct RtlTxDesc {UInt64 addr; UInt32 opts1,opts2;};
static const UInt32 kTxDescMask=1023,kObsPktParsed=1;
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
/* Deliberately NO IOBufferMemoryDescriptor: round17 has no staging buffer, so
 * the template must not type-reference one. If it did, this test would not
 * compile -- which is the point. */
class RTL8125 {public:
 bool useAppleVTD=false; Workloop wl; Workloop *workLoop=&wl; Pci pci; Pci*pciDevice=&pci;
 UInt32 txNextDescIndex=1000, txTailPtr0=1000, txClosePtr0=1003;
 UInt32 txDirtyDescIndex=1000, txDescDoneCount=0; SInt32 txNumFreeDesc=24;
 struct {UInt32 MaxTxDescPtrMask=65535;} linuxData;
 RtlTxDesc txDescArray[1024]{};
 /* The template calls txInterrupt() from the retire timer so completion does
  * not depend on inbound traffic. The harness never lets it reap anything;
  * the tests drive r17TxComplete() explicitly instead. */
 void txInterrupt(){}
 void freePacket(mbuf_t m){assert(!m->frees); m->frees++;m->freedAt=mach_absolute_time();}
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
    g = runpy.run_path(str(ROOT / 'tools/build/patch-lucy-obs.py'))
    assert 'r17TxMap' not in g['OUTPUT_FILL_NEW']  # never after OWN stores
    tx17 = g['select_tx']('17')
    g['select_tx']('16')                            # selection must be reversible
    assert tx17['HOOKS'][0].startswith('if (!r17TxMap(')
    if a.source:
        cpp = Path(a.source).read_text()
        g['select_tx']('17')
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
            (ROOT / 'tools/r17/test-native-main.inc').read_text())
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
