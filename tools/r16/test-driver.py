#!/usr/bin/env python3
"""Compile actual generator TX methods with IOKit plumbing stubs; no model copy.
Run on Mac: python3 tools/r16/test-driver.py [--source generated/RTL812xLucy.cpp]
--emit PATH is useful on Windows without a C++ compiler.
"""
import argparse
from pathlib import Path
import runpy
import subprocess
import tempfile
ROOT = Path(__file__).resolve().parents[2]
T = runpy.run_path(str(ROOT / 'tools/r16/driver-template.py'))
PREFIX = r'''
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <cstdio>
#include <vector>
using UInt32=uint32_t; using UInt64=uint64_t;
using IOReturn=int;
enum {kIOReturnSuccess=0,kIOReturnBadArgument=1,kIOReturnNoMemory=2,
 kIOReturnNoResources=3,kIOReturnBusy=4,kIOReturnNotReady=5};
struct IOService {int refs=1; void retain(){refs++;} void release(){refs--;}};
#include "RTL812xTxMap.hpp"
static UInt64 ticks=100; static UInt64 mach_absolute_time(){return ++ticks;}
struct Mbuf {UInt32 token=7,req=1,len=74; unsigned frees=0; UInt64 freedAt=0; unsigned char data[8192]{}; Mbuf(){for(unsigned i=0;i<8192;i++)data[i]=(unsigned char)i;}}; using mbuf_t=Mbuf*;
static UInt32 mbuf_pkthdr_len(mbuf_t m){return m->len;}
static bool copyFail=false;
static int mbuf_copydata(mbuf_t m,size_t o,size_t n,void*p){if(copyFail)return 1;assert(o+n<=m->len);memcpy(p,m->data+o,n);return 0;}
using IOByteCount=UInt64;
static const int kernel_task=0,kIODirectionOut=1,kIOMemoryPhysicallyContiguous=2,kIOMemoryHostPhysicallyContiguous=4,kIOMemoryMapperNone=8;
static bool prepareFail=false,completeFail=false,badAlignment=false;
static unsigned nativeAlive=0,completeCalls=0; static UInt64 nextPA=0x600000000ULL,lastNativeRelease=0;
struct IOBufferMemoryDescriptor {unsigned char data[4096]{};UInt64 pa;bool prepared=false;
 static IOBufferMemoryDescriptor*inTaskWithOptions(int,int,size_t n,size_t align){assert(n==4096&&align==4096);auto*p=new IOBufferMemoryDescriptor;p->pa=nextPA+(badAlignment?1:0);nextPA+=4096;nativeAlive++;return p;}
 int prepare(){if(prepareFail)return 88;prepared=true;return 0;}
 int complete(){assert(prepared);completeCalls++;if(completeFail)return 88;prepared=false;return 0;}
 void release(){assert(!prepared);nativeAlive--;lastNativeRelease=mach_absolute_time();delete this;}
 void*getBytesNoCopy(){return data;} UInt64 getLength(){return 4096;}
 UInt64 getPhysicalSegment(int,IOByteCount*len,int){*len=4096;return pa;}
};
static void *IOMalloc(size_t n){return calloc(1,n);}
static void IOFree(void*p,size_t){free(p);}
#define IOLog(...) ((void)0)
#define OSMemberFunctionCast(type,obj,method) 0
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
class RTL8125 {public:
 bool useAppleVTD=false; Workloop wl; Workloop *workLoop=&wl; Pci pci; Pci*pciDevice=&pci;
 UInt32 txNextDescIndex=1023,txTailPtr0=1023,txClosePtr0=1025;
 struct {UInt32 MaxTxDescPtrMask=65535;} linuxData;
 RtlTxDesc txDescArray[1024]{};
 void freePacket(mbuf_t m){assert(!m->frees); m->frees++;m->freedAt=mach_absolute_time();}
 UInt32 obsParseBiz(mbuf_t m,UInt32,bool,UInt32*t,UInt32*r,UInt32*f){
 *t=m->token; *r=m->req; *f=0; return 1;}
 void setProperty(const char*,OSData*){}
 void setProperty(const char*,const char*){}
 void setProperty(const char*,UInt64,int){}
'''
TEST = r'''
static int mapMode=0,retireMode=0,maps=0,retires=0;
static IOReturn backend(void*,uint32_t op,r16tx::Request*r){
 if(op==r16tx::kRetire){retires++; if(retireMode)return 88;
 r->tRetire=mach_absolute_time(); return 0;}
 maps++; if(mapMode==1)return 99;
 r->handle=100+maps; r->tMap=mach_absolute_time();
 for(unsigned i=0;i<r->count;i++) r->iova[i]={0x1000000000ULL+i*8192+(r->physical[i].address&4095),r->physical[i].length};
 if(mapMode==2)return 99;
 if(mapMode==3)r->iova[0].length++;
 return 0;
}
static void install(RTL8125&d,IOService&o){
 d.r16Tx=nullptr;
 r16tx::Configure c{}; c.version=1;c.bytes=sizeof(c);c.op=r16tx::kInstall;
 c.bdf=0x2500;c.token=7;c.deadline=100000;c.callback=backend;c.context=&o;c.owner=&o;
 assert(!d.r16TxConfigure(&c));assert(o.refs==2);
}
static r16tx::Configure control(unsigned op){r16tx::Configure c{};
 c.version=1;c.bytes=sizeof(c);c.op=op;return c;}
static void finish(RTL8125&d,IOService&o){auto c=control(r16tx::kDisarm);
 assert(!d.r16TxConfigure(&c));c.op=r16tx::kDetach;
 assert(!d.r16TxConfigure(&c));assert(o.refs==1);d.r16TxStop();}
#include "test-staging-main.inc"
'''
def main():
 p=argparse.ArgumentParser();p.add_argument('--emit');p.add_argument('--source');a=p.parse_args()
 # Structural integration checks validate the real generator placements.
 g=runpy.run_path(str(ROOT/'tools/apply-lucy-obs2.py'))
 assert 'r16TxMap' not in g['OUTPUT_FILL_NEW']  # never after OWN stores
 if a.source:
  cpp=Path(a.source).read_text()
  output=cpp[cpp.index('IOReturn RTL8125::outputStart('):cpp.index('void RTL8125::txInterrupt()')]
  assert output.index('getPhysicalSegmentsWithCoalesce')<output.index('r16TxMap(m,')<output.index('OSAddAtomic(-numSegs')<output.index('firstDesc->opts1 |= DescOwn')<output.index('r16TxPosted(m)')
  assert 'r16TxComplete(txDirtyDescIndex);' in cpp
  assert g['body_is_current'](cpp)==(True,None)
 code=PREFIX+T['MEMBERS']+'\n};\n'+T['METHODS']+TEST
 if a.emit:Path(a.emit).write_text(code);return
 with tempfile.TemporaryDirectory() as tmp:
  src=Path(tmp)/'test.cpp';src.write_text(code);exe=Path(tmp)/'test'
  subprocess.run(['clang++','-std=c++17','-fsanitize=address,undefined','-I',str(ROOT/'tools/lucy-obs'),'-I',str(ROOT/'tools/r16'),str(src),'-o',str(exe)],check=True)
  # State and mock timers intentionally survive stop's fail-closed test.
  import os
  env=dict(os.environ,ASAN_OPTIONS='detect_leaks=0')
  subprocess.run([str(exe)],check=True,env=env)
if __name__=='__main__':main()
