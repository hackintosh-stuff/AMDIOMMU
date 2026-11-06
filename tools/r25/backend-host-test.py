#!/usr/bin/env python3
"""Compile the real Round25 TX backend methods against host-only IOKit/MMIO stubs.

Run: python3 tools/r25/backend-host-test.py --compiler g++
The C++ bodies are extracted from the current kext sources, not reimplemented.
This checks backend ownership/history and cursor handoff; it does not compile
a macOS kext or emulate the NIC, IOKit lifecycle, DMA coherency, or hardware.
"""
import argparse
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def section(source, start, end):
    at = source.index(start)
    return source[at:source.index(end, at)]


PREFIX = r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
using UInt8 = unsigned char;
using UInt32 = unsigned int;
using UInt64 = unsigned long long;
using IOByteCount = UInt64;
using addr64_t = UInt64;
using IOReturn = int;
enum { kIOReturnSuccess=0, kIOReturnBadArgument=1, kIOReturnNotReady=2,
       kIOReturnBusy=3, kIOReturnUnsupported=4, kIOReturnIOError=5,
       kIOReturnNoResources=6, kIOMemoryMapperNone=0,
       kIODMAMapWriteAccess=1, kIODMAMapFixedAddress=2,
       kIODMAMapPhysicallyContiguous=4 };
class IOService {};
struct IOLock { bool held=false; };
static void IOLockLock(IOLock *p) { assert(!p->held); p->held=true; }
static void IOLockUnlock(IOLock *p) { assert(p->held); p->held=false; }
static UInt64 clockTick=0;
static UInt64 mach_absolute_time() { return ++clockTick; }
static void OSSynchronizeIO() {}
class OSObject {
public:
    virtual ~OSObject() {}
    void release() { delete this; }
};
class OSData : public OSObject {
public:
    static OSData *withBytes(const void *, unsigned) { return new OSData; }
};
class FakeService {
public:
    OSObject *copyProperty(const char *) { return nullptr; }
};
class IOMemoryDescriptor {
public:
    UInt64 pa[2]={}, bytes[2]={};
    addr64_t getPhysicalSegment(IOByteCount off, IOByteCount *length, unsigned) {
        for (unsigned i=0;i<2;++i) {
            if (off<bytes[i]) { *length=bytes[i]-off; return pa[i]+off; }
            off-=bytes[i];
        }
        *length=0; return 0;
    }
};
class IODMACommand {};
struct IODMAMapSpecification {};
struct IODMAMapPageList { UInt32 pageOffset; };
#include "kext/amd_iommu_tx_core.hpp"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wenum-compare"
#include "tools/lucy-obs/RTL812xTxMapNative.hpp"
#pragma GCC diagnostic pop
#include "tools/lucy-obs/AMDAliveTxDomainNative.hpp"
#include "tools/lucy-obs/RTL812xRxMap.hpp"
'''

MMIO = r'''
static UInt32 commandMemory[M23_CMD_BUF_SIZE/4+4];
static UInt64 semaphore=0, hardwareHead=0;
static bool signalCompletion=true;
static UInt32 tailWrites=0;
static UInt64 mmioRead64(volatile UInt8 *, UInt32 off) {
    assert(off==M2B2_OFF_CMD_HEAD); return hardwareHead;
}
static void mmioWrite64(volatile UInt8 *, UInt32 off, UInt64 tail) {
    assert(off==M2B2_OFF_CMD_TAIL);
    assert(tail<M23_CMD_BUF_SIZE && !(tail&15));
    ++tailWrites;
    const UInt32 cw=((UInt32)tail+M23_CMD_BUF_SIZE-16)%M23_CMD_BUF_SIZE/4;
    assert(commandMemory[cw+1]>>28==M2B2_CMD_COMPL_WAIT);
    hardwareHead=tail;
    if (signalCompletion)
        semaphore=((UInt64)commandMemory[cw+3]<<32)|commandMemory[cw+2];
}
class org_maz1_AMDMapperProbe {
public:
    struct R17Domain;
    R17Domain *fR17=nullptr;
    struct { UInt32 reserved=0; } fR15Request;
    FakeService *fR15Service=nullptr;
    UInt32 fStdMapCalls=0, fStdMapOk=0, fStdMapRejects=0, fStdUnmapCalls=0,
        fStdUnmapOk=0, fStdPageRuns=0, fStdFragRejects=0, fStdOffsetRejects=0,
        fStdRuns=0, fStdMaxRuns=0, fStdDiscontig=0, fStdCapRejects=0;
    UInt64 mapMark=0;
    static IOReturn r17Callback(void *, UInt32, r17tx::Request *);
    void r17SyncCommand(void *);
    void r17Export(void *);
    IOReturn r18StdMap(IOMemoryDescriptor *, uint64_t, uint64_t, uint32_t,
        const IODMAMapSpecification *, IODMACommand *, const IODMAMapPageList *,
        uint64_t *, uint64_t *);
    IOReturn r18StdUnmap(IOMemoryDescriptor *, IODMACommand *, uint64_t, uint64_t);
    void setProperty(const char *, const char *) {}
    void setProperty(const char *, OSObject *) {}
    void setProperty(const char *name, UInt64 value, unsigned) {
        assert(std::strcmp(name,"m2-3c-map-mark")==0); mapMark=value;
    }
    void publishStdStats() {}
    void r17PublishWindow() {}
};
static void setHexProperty(org_maz1_AMDMapperProbe *, const char *, UInt64) {}
'''

TESTS = r'''
struct Fixture {
    org_maz1_AMDMapperProbe self;
    org_maz1_AMDMapperProbe::R17Domain domain{};
    IOLock lock;
    UInt64 leaves[amdtx::kPages]={};
    UInt8 fakeMMIO=0;
    M2B2CmdCtx caller{};
    Fixture() {
        std::memset(commandMemory,0,sizeof(commandMemory));
        commandMemory[M23_CMD_BUF_SIZE/4]=0xfeedbeef;
        semaphore=hardwareHead=tailWrites=0; signalCompletion=true;
        caller.buf=commandMemory; caller.sem=&semaphore; caller.semPA=0x1000;
        domain.lock=&lock; domain.mmio=&fakeMMIO;
        domain.pt=domain.leaves=leaves; domain.ptBytes=sizeof(leaves);
        domain.installed=domain.accepting=true;
        domain.snapshot.devid=0x3700;
        domain.command=caller;
        self.fR17=&domain; self.fR15Request.reserved=0x2501;
    }
    void handoff() { self.r17SyncCommand(&caller); }
    r17tx::Request request(UInt32 id) {
        r17tx::Request r{};
        r.version=r17tx::kVersion; r.bytes=sizeof(r); r.bdf=0x3700;
        r.token=self.fR15Request.reserved; r.reqId=id; r.count=2;
        r.physical[0]={0x800000ULL+id*0x10000ULL+64,42};
        r.physical[1]={0x800000ULL+id*0x10000ULL+0x2100,1472};
        return r;
    }
    IOReturn call(UInt32 op,r17tx::Request &r) {
        return self.r17Callback(&self,op,&r);
    }
};

static void commandHandoff() {
    Fixture f;
    assert(m2b2Submit(&f.fakeMMIO,&f.caller,"inv-all",0,0,0,0));
    // Install takes a copy, then the caller owns the two entry invalidations.
    f.domain.command=f.caller;
    assert(m2b2Submit(&f.fakeMMIO,&f.caller,"inv-dev-entry",0,0,0,0));
    signalCompletion=false;
    assert(!m2b2Submit(&f.fakeMMIO,&f.caller,"inv-iommu-pages",0,0,0,0));
    f.self.r17Export(&f.caller); // no handoff occurred on this real failure path
    assert(f.caller.failed && f.caller.completionSequence==3);
    assert(f.caller.submits==3 && f.caller.completed==2);
    assert(std::strcmp(f.caller.failReason,"inv-iommu-pages")==0);
    assert(f.domain.command.failed && f.domain.snapshot.commandSubmits==3);
    assert(f.domain.snapshot.completionSequence==3 && !f.lock.held);

    Fixture g;
    for(unsigned i=0;i<3;++i)
        assert(m2b2Submit(&g.fakeMMIO,&g.caller,"entry",0,0,0,0));
    g.handoff();
    assert(g.domain.commandOwned && g.domain.command.completionSequence==3);
    auto request=g.request(1);
    assert(g.call(r17tx::kMap,request)==kIOReturnSuccess);
    assert(g.call(r17tx::kRetire,request)==kIOReturnSuccess);
    assert(g.caller.completionSequence==3);
    g.self.r17Export(&g.caller);
    assert(g.caller.completionSequence==5 && g.caller.tail==160);
    assert(g.caller.submits==5 && g.caller.completed==5 && !g.lock.held);
    assert(std::strcmp(g.caller.records[4].label,"r17-retire-slot0")==0);
    std::puts("command ownership: entry-abort and normal handoff/export PASS");
}

static const unsigned retireOrder[4]={2,0,3,1};
static void checkHistory(const Fixture &f,bool standard) {
    const auto &d=f.domain; const auto &s=d.snapshot;
    assert(d.mapsOk==512 && d.retires==512 && d.liveOwner==0);
    assert(d.maxLiveOwner==4 && d.slotLive==0 && d.slotsUsed==15);
    assert(s.count==32 && s.historyTotal==512 && s.historyStart==480);
    for(unsigned k=0;k<4;++k) assert(d.slotUses[k]==128);
    for(unsigned seq=480;seq<512;++seq) {
        const auto &r=s.records[seq%32];
        const UInt64 id=(seq/4)*4+retireOrder[seq%4]+1;
        assert(r.handle==id && r.status==3);
        assert(standard ? r.req==0 : r.req==id);
        assert(r.mapCommand.expected==r.mapCommand.observed);
        assert(r.retireCommand.expected==r.retireCommand.observed);
        assert(r.tMapPublish<r.tMapInv && r.tMapInv<r.tClearPublish);
        assert(r.tClearPublish<r.tRetireInv);
    }
    assert(d.command.submits==1024 && d.command.completed==1024);
    assert(d.command.wraps==4 && d.command.postWrapCompleted==769);
    assert(d.command.completionSequence==1024 && d.command.tail==0);
    for(unsigned i=0;i<amdtx::kPages;++i) assert(f.leaves[i]==0);
    assert(commandMemory[M23_CMD_BUF_SIZE/4]==0xfeedbeef);
}

static void directHistory() {
    Fixture f; f.handoff();
    for(unsigned batch=0;batch<128;++batch) {
        r17tx::Request requests[4];
        for(unsigned k=0;k<4;++k) {
            requests[k]=f.request(batch*4+k+1);
            assert(f.call(r17tx::kMap,requests[k])==kIOReturnSuccess);
            assert(requests[k].handle==batch*4+k+1);
        }
        assert(f.domain.liveOwner==4 && f.domain.slotLive==15);
        for(unsigned n=0;n<4;++n) {
            const unsigned slot=retireOrder[n];
            assert(f.call(r17tx::kRetire,requests[slot])==kIOReturnSuccess);
            for(unsigned next=n+1;next<4;++next) {
                const unsigned live=retireOrder[next];
                assert(f.domain.slotRecord[live].handle==requests[live].handle);
                assert(f.domain.slotRecord[live].status==1);
                assert(f.leaves[live*amdtx::kPagesPerSlot]!=0);
            }
        }
    }
    checkHistory(f,false);
    f.self.r17Export(&f.caller);
    // The first four Maps fill records 0..3. Retire labels must outlive all
    // subsequent callback frames, because diagnostics are exported only now.
    for(unsigned k=0;k<4;++k) {
        char expected[32];
        std::snprintf(expected,sizeof(expected),"r17-retire-slot%u",retireOrder[k]);
        assert(std::strcmp(f.caller.records[4+k].label,expected)==0);
    }
    assert(f.domain.snapshot.commandWraps==4 && f.caller.completed==1024);
    std::puts("direct backend: 512 requests, 4 owners, 32 retained records, 4 wraps PASS");
}

static IOMemoryDescriptor descriptor(Fixture &f,unsigned id) {
    auto r=f.request(id); IOMemoryDescriptor memory;
    for(unsigned k=0;k<2;++k) {
        memory.pa[k]=r.physical[k].address; memory.bytes[k]=r.physical[k].length;
    }
    return memory;
}
static IOReturn standardMap(Fixture &f,IOMemoryDescriptor &memory,
                           uint64_t &address,uint64_t &length) {
    IODMACommand command;
    return f.self.r18StdMap(&memory,0,1514,0,nullptr,&command,nullptr,&address,&length);
}
static void standardHistory() {
    Fixture f; f.handoff();
    f.domain.stdMode=true; f.domain.stdMapper=&f.self;
    for(unsigned batch=0;batch<128;++batch) {
        uint64_t addresses[4],lengths[4];
        for(unsigned k=0;k<4;++k) {
            auto memory=descriptor(f,batch*4+k+1);
            const UInt64 mark0=f.self.mapMark;
            assert(standardMap(f,memory,addresses[k],lengths[k])==kIOReturnSuccess);
            const UInt64 mark1=f.self.mapMark;
            assert((mark1>>32)==(mark0>>32)+1);
            assert((UInt32)mark1==batch*4+k+1);
            assert(lengths[k]>1514); // real fragmented mapLength contract
        }
        assert(f.domain.liveOwner==4);
        for(unsigned n=0;n<4;++n) {
            const unsigned k=retireOrder[n];
            assert(f.self.r18StdUnmap(nullptr,nullptr,addresses[k],lengths[k])==kIOReturnSuccess);
            for(unsigned next=n+1;next<4;++next) {
                const unsigned live=retireOrder[next];
                assert(f.domain.slotRecord[live].status==1);
                assert(f.leaves[live*amdtx::kPagesPerSlot]!=0);
            }
        }
    }
    checkHistory(f,true);
    f.self.r17Export(&f.caller);
    for(unsigned k=0;k<4;++k) {
        char expected[32];
        std::snprintf(expected,sizeof(expected),"r18-std-unmap-slot%u",retireOrder[k]);
        assert(std::strcmp(f.caller.records[4+k].label,expected)==0);
    }
    assert(f.self.fStdMapOk==512 && f.self.fStdUnmapOk==512);
    std::puts("standard backend: handles 1..512, fragmented map/unmap, bounded history PASS");
}

static void failedOwnerRemains(bool standard,bool failMap) {
    Fixture f; f.handoff();
    f.domain.stdMode=standard; f.domain.stdMapper=&f.self;
    auto request=f.request(1); auto memory=descriptor(f,1);
    uint64_t address=0,length=0;
    signalCompletion=!failMap;
    IOReturn result=standard ? standardMap(f,memory,address,length)
                            : f.call(r17tx::kMap,request);
    if (failMap) assert(result==kIOReturnIOError);
    else {
        assert(result==kIOReturnSuccess); signalCompletion=false;
        result=standard ? f.self.r18StdUnmap(nullptr,nullptr,address,length)
                        : f.call(r17tx::kRetire,request);
        assert(result==kIOReturnIOError);
    }
    assert(f.domain.liveOwner==1 && f.domain.slotLive==1);
    assert(!f.domain.accepting && f.domain.command.failed);
    assert(f.domain.snapshot.historyTotal==0 && f.domain.snapshot.active==1);
    assert(f.domain.slotRecord[0].handle==1);
    assert(f.domain.slotRecord[0].status==(failMap ? 4u : 9u));
    const UInt32 before=tailWrites;
    if (standard) {
        assert(f.self.mapMark==0x100000001ULL);
        assert(standardMap(f,memory,address,length)!=kIOReturnSuccess);
    } else {
        auto next=f.request(2); assert(f.call(r17tx::kMap,next)!=kIOReturnSuccess);
    }
    assert(tailWrites==before && f.domain.liveOwner==1);
    f.self.r17Export(&f.caller);
    assert(f.caller.failed && f.domain.snapshot.liveOwners==1);
    if (!failMap)
        assert(std::strcmp(f.caller.failReason,standard ? "r18-std-unmap-slot0"
                                                       : "r17-retire-slot0")==0);
}
int main() {
    commandHandoff();
    directHistory();
    standardHistory();
    failedOwnerRemains(false,true); failedOwnerRemains(false,false);
    failedOwnerRemains(true,true); failedOwnerRemains(true,false);
    std::puts("actual direct/standard map and unmap timeout paths retain owner and history PASS");
}
'''


def harness():
    header = (ROOT / 'kext/AMDMapperProbeInternal.hpp').read_text(encoding='utf-8')
    tx = (ROOT / 'kext/AMDMapperProbeTxDebug.cpp').read_text(encoding='utf-8')
    names = ['M23_CMD_BUF_SIZE', 'M2B2_CMD_LOG_MAX', 'M2B2_CMD_COMPL_WAIT',
             'M2B2_OFF_CMD_HEAD', 'M2B2_OFF_CMD_TAIL', 'M2B2_CMD_INV_IOMMU_PAGES',
             'M2B2_CMD_PDE_MASK', 'M2B2_CMD_ALL_PAGES_ADDR', 'M2B2_IDENTITY_LIMIT']
    constants = '\n'.join(re.search(r'^#define\s+' + n + r'\s+\S+', header, re.M).group(0)
                          for n in names)
    # Short polling limit only in the host fixture; all production capacities
    # and ABI layouts come from the real files.
    text = PREFIX + constants + '\n#define M2B1_LOOP_TIMEOUT 32\n'
    text += section(header, 'struct LayoutRun {', '// ---- kNicPaths')
    text += section(header, 'struct M2B2CmdRecord {', '// ---- m2b2ResetEventLog')
    text += MMIO
    text += section(header, 'static inline void m2b2WriteCmd(', '// ---- m2b2InvAddress')
    text += section(header, 'static inline UInt64 m2b2InvAddress()', '// ---- M2B2 measurement')
    text += section(header, 'static inline bool m2b2Submit(', '// ---- m2b2ReadBar64')
    text += section(tx, 'struct org_maz1_AMDMapperProbe::R17Domain {',
                    '// The pool owns mbufs;')
    text += section(tx, 'static const UInt32 kNoSlot', '// Round18: is the standard')
    text += section(tx, 'void org_maz1_AMDMapperProbe::r17SyncCommand(',
                    'void org_maz1_AMDMapperProbe::r17PublishWindow(')
    text += section(tx, 'void org_maz1_AMDMapperProbe::r17Export(',
                    'void org_maz1_AMDMapperProbe::r17Release(')
    text += section(tx, 'static inline UInt64 r18LeafFor(',
                    'bool org_maz1_AMDMapperProbe::r18StdReady(')
    text += section(tx, 'IOReturn org_maz1_AMDMapperProbe::r18StdMap(',
                    '// ================= Round28:')
    return text + TESTS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', default=shutil.which('g++') or shutil.which('clang++'))
    parser.add_argument('--emit', type=Path, help='emit the exact standalone C++ harness')
    parser.add_argument('--sanitize', action='store_true', help='enable host ASan/UBSan')
    args = parser.parse_args()
    source = harness()
    if args.emit:
        args.emit.write_text(source, encoding='utf-8')
        return
    if not args.compiler:
        parser.error('No host C++ compiler found; use --compiler or --emit')
    with tempfile.TemporaryDirectory(prefix='r25-backend-') as directory:
        cpp = Path(directory) / 'backend.cpp'
        binary = Path(directory) / 'backend-test'
        cpp.write_text(source, encoding='utf-8')
        command = [args.compiler, '-std=c++11', '-Wall', '-Wextra', '-Werror',
                   '-I', str(ROOT), str(cpp), '-o', str(binary)]
        if args.sanitize:
            command += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-g']
        subprocess.run(command, check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == '__main__':
    main()
