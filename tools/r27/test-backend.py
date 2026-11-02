#!/usr/bin/env python3
"""Compile actual R27 RX mapper methods against the existing R25 host stubs.

This executes the production layout/identity/stripe/unmap code and real command
ring helpers. Begin/finish/release bodies also compile against API placeholders.
It does not emulate IOKit command lifetime, Lucy, or NIC DMA.
"""
import argparse
import importlib.util
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('r25_backend', ROOT / 'tools/r25/backend-host-test.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

DECLARATIONS = r'''
    struct R27RxDomain;
    R27RxDomain *fR27Rx=nullptr;
    UInt64 fR15InvTicks=0;
    bool r27RxCandidate(IOMemoryDescriptor *, IODMACommand *) const;
    bool r27RxOwnsAddress(uint64_t) const;
    bool r27RxTranslate(uint64_t, uint64_t *) const;
    IOReturn r27RxMap(IOMemoryDescriptor *,uint64_t,uint64_t,uint32_t,
        const IODMAMapSpecification *,IODMACommand *,const IODMAMapPageList *,
        uint64_t *,uint64_t *);
    IOReturn r27RxUnmap(IOMemoryDescriptor *,IODMACommand *,uint64_t,uint64_t);
    bool r27RxRequested() const;
    bool r27RxBegin();
    void r27RxReady();
    bool r27RxFinish(UInt32);
    bool r29WaitTailDone(UInt32);
    void r27RxExport();
    void r27RxRelease();
    IOReturn r27RxControl(UInt32);
    bool r18StdReady() const { return fR17 != nullptr; }
    R27ProbeTimer *fM22b2Timer=nullptr;
'''

# Lifecycle bodies are compiled too. These API placeholders are not an IOKit
# emulator; the executable assertions below target actual mapper callbacks.
LIFECYCLE_APIS = r'''
class OSSymbol;
class IOService {
public:
    unsigned refs=1;
    void retain() { ++refs; }
    void release() { assert(refs); --refs; }
    IOReturn callPlatformFunction(const OSSymbol *,bool,void *,void *,void *,void *)
        { return kIOReturnSuccess; }
};
class IOWorkLoop {
    friend class IOEventSource;
protected:
    void openGate() { assert(depth); --depth; ++opens; }
    void closeGate() { ++depth; ++closes; }
public:
    unsigned refs=1, depth=1, opens=0, closes=0;
    void retain() { ++refs; }
    void release() { assert(refs); --refs; }
    bool inGate() { return depth != 0; }
};
class IOEventSource {
protected:
    void openGate() { loop->openGate(); }
    void closeGate() { loop->closeGate(); }
public:
    IOWorkLoop *loop=nullptr;
    unsigned refs=1;
    void retain() { ++refs; }
    void release() { assert(refs); --refs; }
    IOWorkLoop *getWorkLoop() const { return loop; }
};
class IOTimerEventSource : public IOEventSource {
public:
    using Action=void (*)(void *, IOTimerEventSource *);
};
#define OSDeclareDefaultStructors(type) public: type() = default
'''

DMA_APIS = r'''
class IODMACommand {
public:
    enum { kMapped=0 };
    struct Segment64 { UInt64 fIOVMAddr, fLength; };
    static IODMACommand *withSpecification(unsigned,unsigned,unsigned,unsigned,
        unsigned,unsigned,void *,void *) { return new IODMACommand; }
    IOReturn setMemoryDescriptor(IOMemoryDescriptor *,bool) { return kIOReturnSuccess; }
    IOReturn gen64IOVMSegments(UInt64 *,Segment64 *,UInt32 *) { return kIOReturnSuccess; }
    IOReturn complete(bool,bool) { return kIOReturnSuccess; }
    IOReturn clearMemoryDescriptor(bool) { return kIOReturnSuccess; }
    void release() { delete this; }
};
class OSSymbol : public OSObject {
public:
    static const OSSymbol *withCString(const char *) { return new OSSymbol; }
    void release() const { delete this; }
};
static void *IOMalloc(size_t bytes) { return std::malloc(bytes); }
static void IOFree(void *p,size_t) { std::free(p); }
static void nanoseconds_to_absolutetime(UInt64 n,UInt64 *ticks) { *ticks=n; }
static void absolutetime_to_nanoseconds(UInt64 t,UInt64 *ns) { *ns=t; }
static void IOSleep(unsigned ms) { clockTick+=ms*1000000ULL; }
static bool r17ModeRequested(const char *,size_t) { return true; }
'''

TESTS = r'''
struct Fixture {
    org_example_AMDMapperProbe self;
    org_example_AMDMapperProbe::R17Domain domain{};
    org_example_AMDMapperProbe::R27RxDomain rx{};
    IOLock lock;
    UInt64 leaves[512]={};
    UInt8 fakeMMIO=0;
    IOMemoryDescriptor memory[r27rx::kCount];
    IODMACommand command[r27rx::kCount];
    Fixture() {
        std::memset(commandMemory,0,sizeof(commandMemory));
        commandMemory[M23_CMD_BUF_SIZE/4]=0xfeedbeef;
        semaphore=hardwareHead=tailWrites=0; signalCompletion=true;
        domain.lock=&lock; domain.mmio=&fakeMMIO;
        domain.pt=domain.leaves=leaves; domain.ptBytes=sizeof(leaves);
        domain.installed=domain.accepting=domain.stdMode=domain.commandOwned=true;
        domain.stdMapper=&self;
        domain.command.buf=commandMemory; domain.command.sem=&semaphore;
        domain.command.semPA=0x1000; domain.command.domid=7;
        self.fR17=&domain; self.fR27Rx=&rx;
        rx.snapshot.count=r27rx::kCount;
        for(unsigned j=0;j<amdtx::kPages;++j) leaves[j]=0xa5000000ULL+j;
        for(unsigned i=0;i<r27rx::kCount;++i) {
            memory[i].pa[0]=0x800000000ULL+i*0x10000ULL+(i%2 ? 384 : 0);
            memory[i].bytes[0]=r27rx::kCapacity;
            rx.memory[i]=&memory[i]; rx.command[i]=&command[i];
            auto &w=rx.snapshot.records[i];
            w.pa=memory[i].pa[0]; w.capacity=r27rx::kCapacity;
            w.entryId=1024+i; w.flags=r27rx::kMapRegistered;
        }
    }
    IOReturn map(unsigned i,uint32_t options=kIODMAMapWriteAccess) {
        uint64_t address=0,length=0;
        IODMAMapPageList list{(UInt32)(memory[i].pa[0]&4095)};
        return self.r27RxMap(&memory[i],0,r27rx::kCapacity,options,nullptr,
            &command[i],&list,&address,&length);
    }
    IOReturn unmap(unsigned i) {
        const auto &w=rx.snapshot.records[i];
        return self.r27RxUnmap(&memory[i],&command[i],w.iova,w.mapLength);
    }
};

static void normalBatch() {
    static_assert(r27rx::kVersion == 3, "Round29 RX ABI3");
    static_assert(sizeof(r27rx::Cycle) == 40, "first four cycle samples");
    static_assert(sizeof(r27rx::Witness) == 272, "cyclic witness");
    static_assert(sizeof(r27rx::Snapshot) == 19536, "driver snapshot");
    static_assert(sizeof(r27rx::Request) == 21632, "control request");
    static_assert(sizeof(r27rx::BackendSnapshot) == 12864, "backend unchanged");
    Fixture f;
    for(unsigned i=0;i<r27rx::kCount;++i) {
        assert(f.self.r27RxCandidate(&f.memory[i],&f.command[i]));
        assert(f.map(i)==kIOReturnSuccess);
        const auto &w=f.rx.snapshot.records[i];
        assert(w.iova==r27rx::kIovaBase+i*8192ULL+(w.pa&4095));
        assert(w.mapLength==4096 && w.pages==(i%2 ? 2u : 1u));
        assert(w.flags==7 && w.mapResult==0 && w.tMapPublish<w.tMapInv);
        assert(w.mapCommand.expected==i+1 && w.mapCommand.observed==i+1);
        assert(w.mapCommand.tComplete==w.tMapInv);
        assert(w.mapCommand.d[0]==0 && w.mapCommand.d[1]==((3u<<28)|7u) &&
               w.mapCommand.d[2]==0xfffff003u && w.mapCommand.d[3]==0x7fffffffu);
        for(unsigned byte : {0u,4095u}) {
            uint64_t physical=0;
            assert(f.self.r27RxTranslate(w.iova+byte,&physical));
            assert(physical==w.pa+byte);
        }
        for(unsigned p=0;p<w.pages;++p) {
            const auto raw=f.leaves[amdtx::kPages+i*2+p];
            assert((raw&(amdpte::PTE_IR|amdpte::PTE_IW))==
                   (amdpte::PTE_IR|amdpte::PTE_IW));
            assert(amdpte::decodePte(raw,1).outPA==(w.pa&~4095ULL)+p*4096ULL);
        }
    }
    assert(f.rx.snapshot.mapOk==64 && f.rx.snapshot.liveOwners==64);
    assert(f.domain.slotLive==0 && f.domain.liveOwner==0 && f.self.fStdMapOk==0);
    f.rx.installed=true; f.rx.drained=true;
    // Different retirement order proves per-command identity, not newest map.
    for(unsigned n=0;n<r27rx::kCount;++n) {
        unsigned i=(n*17)%r27rx::kCount;
        assert(f.unmap(i)==kIOReturnSuccess);
        const auto &w=f.rx.snapshot.records[i];
        assert(w.flags==15 && w.unmapResult==0);
        assert(w.unmapCommand.expected==65+n && w.unmapCommand.observed==65+n);
        assert(w.mapCommand.expected==i+1 && w.mapCommand.observed==i+1);
        assert(w.unmapCommand.tComplete==w.tUnmapInv);
        assert(w.unmapCommand.d[0]==0 && w.unmapCommand.d[1]==((3u<<28)|7u) &&
               w.unmapCommand.d[2]==0xfffff003u && w.unmapCommand.d[3]==0x7fffffffu);
        assert(w.tMapInv<w.tUnmapPublish && w.tUnmapPublish<w.tUnmapInv);
        assert(!w.clearPte[0] && !w.clearPte[1]);
        uint64_t physical=0;
        assert(!f.self.r27RxTranslate(w.iova,&physical));
    }
    assert(f.rx.snapshot.unmapOk==64 && !f.rx.snapshot.liveOwners);
    assert(f.rx.snapshot.flags==0 && f.domain.command.completed==128);
    for(unsigned i=0;i<amdtx::kPages;++i) assert(f.leaves[i]==0xa5000000ULL+i);
    for(unsigned i=amdtx::kPages;i<512;++i) assert(!f.leaves[i]);
    assert(commandMemory[M23_CMD_BUF_SIZE/4]==0xfeedbeef && !f.lock.held);
    std::puts("R27 production mapper: 64 distinct RX stripes, IW, exact PA, 128 CW, TX untouched PASS");
}

static void identityAndDrain() {
    Fixture f;
    IOMemoryDescriptor foreign;
    IODMACommand foreignCommand;
    assert(!f.self.r27RxCandidate(&foreign,&foreignCommand));
    assert(f.self.r27RxCandidate(&f.memory[0],&foreignCommand));
    uint64_t address=0,length=0;
    assert(f.self.r27RxMap(&f.memory[0],0,4096,kIODMAMapWriteAccess,nullptr,
        &foreignCommand,nullptr,&address,&length)==kIOReturnBadArgument);
    assert(!f.rx.snapshot.liveOwners && !tailWrites);
    assert(f.map(0,0)==kIOReturnBadArgument); // device write is mandatory
    assert(f.map(0)==kIOReturnSuccess);
    f.rx.installed=true;
    const auto &w=f.rx.snapshot.records[0];
    assert(f.unmap(0)==kIOReturnNotReady);
    assert(f.rx.snapshot.liveOwners==1 && f.leaves[amdtx::kPages]);
    f.rx.drained=true;
    assert(f.self.r27RxUnmap(&f.memory[0],&foreignCommand,w.iova,w.mapLength)
        ==kIOReturnBadArgument);
    assert(f.unmap(0)==kIOReturnSuccess && !f.rx.snapshot.liveOwners);
    std::puts("R27 registered object pairs and pre-drain retirement refusal PASS");
}
static void clientGateLifetime() {
    IOService owner;
    IOWorkLoop loop;
    R27ProbeTimer timer;
    timer.loop=&loop;
    for (unsigned depth : {0u, 1u, 2u}) {
        loop.depth=depth;
        const unsigned opens=loop.opens, closes=loop.closes;
        auto earlyReturn = [&]() {
            R27ClientContext client(&owner, &timer);
            assert(owner.refs==2 && timer.refs==2 && loop.refs==2);
            assert(loop.depth==(depth ? depth-1 : 0));
            return;
        };
        earlyReturn();
        assert(loop.depth==depth && owner.refs==1 && timer.refs==1 && loop.refs==1);
        assert(loop.opens==opens+(depth != 0) && loop.closes==closes+(depth != 0));
    }
    { R27ClientContext client(&owner, nullptr); assert(owner.refs==2); }
    assert(owner.refs==1);
    std::puts("R27 client gate access, exact restore and retained lifetimes PASS");
}
int main() { clientGateLifetime(); normalBatch(); identityAndDrain(); }
'''


def harness():
    header = (ROOT / 'kext/AMDMapperProbeInternal.hpp').read_text()
    tx = (ROOT / 'kext/AMDMapperProbeTx.cpp').read_text()
    names = ['M23_CMD_BUF_SIZE', 'M2B2_CMD_LOG_MAX', 'M2B2_CMD_COMPL_WAIT',
             'M2B2_OFF_CMD_HEAD', 'M2B2_OFF_CMD_TAIL', 'M2B2_CMD_INV_IOMMU_PAGES',
             'M2B2_CMD_PDE_MASK', 'M2B2_CMD_ALL_PAGES_ADDR', 'M2B2_IDENTITY_LIMIT']
    constants = '\n'.join(re.search(r'^#define\s+' + n + r'\s+\S+', header, re.M).group(0)
                          for n in names)
    prefix = base.PREFIX.replace('#include <cassert>', '#include <cassert>\n#include <cstdlib>')
    prefix = prefix.replace('kIOReturnNoResources=6,',
                            'kIOReturnNoResources=6, kIOReturnNoMemory=7, kIODirectionIn=8, kIODMACommandOutputHost64=9,')
    prefix = prefix.replace('class IOService {};', LIFECYCLE_APIS)
    prefix += base.section(header, 'class R27ProbeTimer :', '// ---- probeRawMapper')
    prefix = prefix.replace('class IODMACommand {};', DMA_APIS)
    prefix = prefix.replace('class IOMemoryDescriptor {\npublic:', r'''class IOMemoryDescriptor {
public:
    static IOMemoryDescriptor *withPhysicalAddress(UInt64,IOByteCount,unsigned)
        { return new IOMemoryDescriptor; }
    IOReturn prepare(unsigned) { return kIOReturnSuccess; }
    IOReturn complete(unsigned) { return kIOReturnSuccess; }
    void release() { delete this; }
''')
    prefix += 'using IOPhysicalAddress=UInt64;\n'
    prefix += base.section(header, 'static inline UInt64 m2b2NowNS()', '// ---- m2b2WallSecs')
    text = prefix + '#include "tools/lucy-obs/RTL812xRxMap.hpp"\n'
    text += '#include "tools/lucy-obs/RTL812xRxPool.hpp"\n' + constants
    text += '\n#define M2B1_LOOP_TIMEOUT 32\n'
    text += base.section(header, 'struct LayoutRun {', '// ---- kNicPaths')
    text += base.section(header, 'struct M2B2CmdRecord {', '// ---- m2b2ResetEventLog')
    mmio = base.MMIO.replace('    struct R17Domain;', DECLARATIONS + '    struct R17Domain;')
    mmio = mmio.replace('class org_example_AMDMapperProbe {',
                        'class org_example_AMDMapperProbe : public IOService {')
    mmio = mmio.replace('struct { UInt32 reserved=0; } fR15Request;',
                        'r15pool::Request fR15Request{};')
    mmio = mmio.replace('FakeService *fR15Service', 'IOService *fR15Service')
    text += mmio
    text += base.section(header, 'static inline void m2b2WriteCmd(', '// ---- m2b2InvAddress')
    text += base.section(header, 'static inline UInt64 m2b2InvAddress()', '// ---- M2B2 measurement')
    text += base.section(header, 'static inline bool m2b2Submit(', '// ---- m2b2ReadBar64')
    text += base.section(tx, 'struct org_example_AMDMapperProbe::R17Domain {',
                         'bool org_example_AMDMapperProbe::r17Prepare(')
    text += base.section(tx, 'static bool r17Invalidate(',
                         'IOReturn org_example_AMDMapperProbe::r17Callback(')
    text += tx[tx.index('bool org_example_AMDMapperProbe::r27RxRequested()'):]
    return text + TESTS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', default=shutil.which('g++') or shutil.which('clang++'))
    parser.add_argument('--emit', type=Path)
    args = parser.parse_args()
    source = harness()
    if args.emit:
        args.emit.write_text(source)
        return
    if not args.compiler:
        parser.error('No host C++ compiler found')
    with tempfile.TemporaryDirectory(prefix='r27-backend-') as directory:
        cpp = Path(directory) / 'backend.cpp'
        binary = Path(directory) / 'backend-test'
        cpp.write_text(source)
        subprocess.run([args.compiler, '-std=c++17', '-Wall', '-Wextra', '-Werror',
                        '-I', str(ROOT), str(cpp), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == '__main__':
    main()
