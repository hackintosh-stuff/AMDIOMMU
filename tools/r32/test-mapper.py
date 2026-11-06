#!/usr/bin/env python3
"""Run the production dynamic mapper and capacity probe with host IOKit stubs.

The allocator, descriptor layout, standard map/unmap/translate methods, capacity
probe body, and command-ring submission code are extracted from the kext. Only
IOKit object creation and hardware CompletionWait delivery are host adapters.
This proves the normal ownership and reuse path; it is not a macOS kext build
or evidence that a NIC has DMA-read a multi-page packet.
"""
import argparse
import importlib.util
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    'r25_host', ROOT / 'tools/r25/backend-host-test.py')
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


IOKIT = r'''
class org_maz1_AMDMapperProbe;
enum { kIODirectionInOut=3, kIOMemoryPhysicallyContiguous=4,
       kIODMACommandOutputHost64=0 };
static void *kernel_task=nullptr;
class IOMemoryDescriptor {
public:
    UInt64 pa[16]={}, bytes[16]={};
    virtual ~IOMemoryDescriptor() {}
    void release() { delete this; }
    IOReturn prepare(unsigned) { return kIOReturnSuccess; }
    IOReturn complete(unsigned) { return kIOReturnSuccess; }
    UInt64 getLength() const {
        UInt64 total=0; for (unsigned i=0;i<16;++i) total+=bytes[i];
        return total;
    }
    addr64_t getPhysicalSegment(IOByteCount off, IOByteCount *length, unsigned) {
        for (unsigned i=0;i<16;++i) {
            if (off<bytes[i]) { *length=bytes[i]-off; return pa[i]+off; }
            off-=bytes[i];
        }
        *length=0; return 0;
    }
};
class IOBufferMemoryDescriptor : public IOMemoryDescriptor {
public:
    static IOBufferMemoryDescriptor *inTaskWithPhysicalMask(
        void *, unsigned options, IOByteCount length, UInt64 mask) {
        assert(options==(kIODirectionInOut|kIOMemoryPhysicallyContiguous));
        assert(mask==0xFFFFFFFFFFFFF000ULL);
        static UInt64 nextPA=0x80000000ULL;
        auto *p=new IOBufferMemoryDescriptor;
        p->pa[0]=nextPA; p->bytes[0]=length;
        nextPA+=length+4096;
        return p;
    }
};
class IODMACommand {
public:
    struct Segment64 { UInt64 fIOVMAddr, fLength; };
    enum { kMapped=1 };
    org_maz1_AMDMapperProbe *mapper=nullptr;
    IOMemoryDescriptor *memory=nullptr;
    uint64_t mapAddress=0, mapLength=0;
    bool prepared=false;
    static IODMACommand *withSpecification(unsigned, unsigned, unsigned,
        unsigned, unsigned, unsigned, org_maz1_AMDMapperProbe *, void *);
    IOReturn setMemoryDescriptor(IOMemoryDescriptor *, bool);
    IOReturn gen64IOVMSegments(UInt64 *, Segment64 *, UInt32 *);
    IOReturn complete(bool, bool);
    IOReturn clearMemoryDescriptor(bool) {
        assert(!prepared); memory=nullptr; return kIOReturnSuccess;
    }
    void release() { assert(!prepared); delete this; }
};
'''

DMA_ADAPTER = r'''
IODMACommand *IODMACommand::withSpecification(unsigned, unsigned, unsigned,
    unsigned, unsigned, unsigned, org_maz1_AMDMapperProbe *mapper, void *) {
    auto *cmd=new IODMACommand; cmd->mapper=mapper; return cmd;
}
IOReturn IODMACommand::setMemoryDescriptor(IOMemoryDescriptor *md, bool prepare) {
    assert(md && mapper && prepare && !prepared);
    memory=md;
    const IOReturn ret=mapper->r18StdMap(md,0,md->getLength(),0,
        nullptr,this,nullptr,&mapAddress,&mapLength);
    prepared=ret==kIOReturnSuccess;
    return ret;
}
IOReturn IODMACommand::gen64IOVMSegments(UInt64 *offset, Segment64 *segment,
                                      UInt32 *count) {
    assert(prepared && memory && *count==1 && !*offset);
    // The capacity probe uses a physically contiguous descriptor, so IOKit's
    // linear contract is exactly mapAddress + logical offset.
    assert(mapLength==memory->getLength() && memory->bytes[1]==0);
    segment->fIOVMAddr=mapAddress; segment->fLength=memory->getLength();
    *offset=segment->fLength; *count=1;
    return kIOReturnSuccess;
}
IOReturn IODMACommand::complete(bool, bool) {
    assert(prepared);
    const IOReturn ret=mapper->r18StdUnmap(memory,this,mapAddress,mapLength);
    if (ret==kIOReturnSuccess) prepared=false;
    return ret;
}
'''

TESTS = r'''
struct Fixture {
    org_maz1_AMDMapperProbe self;
    org_maz1_AMDMapperProbe::R17Domain *domain;
    IOLock lock;
    UInt64 leaves[amdtx::kPages]={};
    UInt8 fakeMMIO=0;
    M2B2CmdCtx caller{};
    Fixture() : domain(new org_maz1_AMDMapperProbe::R17Domain{}) {
        std::memset(commandMemory,0,sizeof(commandMemory));
        commandMemory[M23_CMD_BUF_SIZE/4]=0xfeedbeef;
        semaphore=hardwareHead=tailWrites=0; signalCompletion=true;
        caller.buf=commandMemory; caller.sem=&semaphore; caller.semPA=0x1000;
        domain->lock=&lock; domain->mmio=&fakeMMIO;
        domain->pt=domain->leaves=leaves; domain->ptBytes=sizeof(leaves);
        domain->installed=domain->accepting=domain->stdMode=domain->stopOk=true;
        domain->stdMapper=&self;
        domain->snapshot.version=r17domain::kVersion;
        domain->snapshot.bytes=sizeof(domain->snapshot);
        domain->snapshot.devid=0x3700;
        domain->snapshot.iovaBase=amdtx::kBase;
        domain->snapshot.iovaBytes=amdtx::kPages*4096ULL;
        self.fR17=domain;
        self.r17SyncCommand(&caller);
    }
    ~Fixture() {
        assert(!domain->liveOwner && !domain->allocator.livePages && !lock.held);
        for (unsigned i=0;i<amdtx::kPages;++i) assert(!leaves[i]);
        assert(commandMemory[M23_CMD_BUF_SIZE/4]==0xfeedbeef);
        delete domain;
    }
};

static void productionCapacityProbe() {
    Fixture f;
    auto &d=*f.domain;
    assert(f.self.r32CapacityProbe());
    f.self.r17Export(&f.caller);
    const auto &s=d.snapshot;
    assert(s.probePassed && s.probeReused);
    assert(s.probeMaps==9 && s.probeUnmaps==9);
    assert(s.mapsTotal==9 && s.retiresTotal==9 && s.historyTotal==9);
    assert(s.probePeakOwners==8 && s.maxLiveOwners==8);
    assert(s.probeMaxPages==8 && s.maxMappedPages==8 && s.peakPages==15);
    assert(!s.liveOwners && !s.livePages && s.reusedAllocations==1);
    assert(s.probeFirst.pages==8 && s.probeReuse.pages==8);
    assert(s.probeFirst.status==3 && s.probeReuse.status==3);
    assert(s.probeFirst.basePage==s.probeReuse.basePage);
    assert(s.probeFirst.tRetireInv<s.probeReuse.tMapPublish);
    assert(s.probeStart<s.probeFirst.tMapPublish && s.probeReuse.tRetireInv<s.probeEnd);
    // Record 1 follows an eight-page mapping: its active-record index is 1,
    // its allocation base is page 8. No address derives from the record index.
    assert(s.records[1].recordIndex==1 && s.records[1].basePage==8);
    for (unsigned i=0;i<9;++i) {
        const auto &r=s.records[i];
        assert(r.status==3 && r.mapCommand.expected==r.mapCommand.observed);
        assert(r.retireCommand.expected==r.retireCommand.observed);
        assert(r.tMapPublish<r.tMapInv && r.tMapInv<r.tClearPublish);
        assert(r.tClearPublish<r.tRetireInv);
        for (unsigned j=0;j<r.pages;++j) {
            assert(r.mapPte[j] && !r.clearPte[j]);
            assert(amdpte::decodePte(r.mapPte[j],1).outPA==r.physical[j]);
        }
    }
    assert(f.caller.completionSequence==18 && f.caller.completed==18);
    std::puts("production capacity probe: 8 live, 8-page map, 9/9 completed, reuse PASS");
}

static void normalVariableMappings() {
    Fixture f;
    IOMemoryDescriptor wide, neighbor, replacement;
    IODMACommand wideCommand, neighborCommand, replacementCommand;
    for (unsigned i=0;i<16;++i) {
        wide.pa[i]=0x90000000ULL+i*0x20000ULL;
        wide.bytes[i]=4096;
    }
    neighbor.pa[0]=0xa0000000ULL; neighbor.bytes[0]=3*4096;
    replacement.pa[0]=0xb0000000ULL; replacement.bytes[0]=6*4096;
    uint64_t wideAddress=0, wideLength=0, neighborAddress=0, neighborLength=0;
    uint64_t replacementAddress=0, replacementLength=0, pa=0;
    assert(f.self.r18StdMap(&wide,0,wide.getLength(),kIODMAMapWriteAccess,
        nullptr,&wideCommand,nullptr,&wideAddress,&wideLength)==kIOReturnSuccess);
    assert(f.self.r18StdMap(&neighbor,0,neighbor.getLength(),0,
        nullptr,&neighborCommand,nullptr,&neighborAddress,&neighborLength)==kIOReturnSuccess);
    assert(wideAddress==amdtx::kBase && neighborAddress==amdtx::kBase+16*4096ULL);
    assert(f.domain->allocator.livePages==19 && f.domain->liveOwner==2);
    for (unsigned i=0;i<16;++i) {
        assert(f.self.r18StdTranslate(wideAddress+i*4096ULL+37,&pa));
        assert(pa==wide.pa[i]+37);
    }
    assert(f.self.r18StdUnmap(&wide,&wideCommand,wideAddress,wideLength)==kIOReturnSuccess);
    assert(f.self.r18StdTranslate(neighborAddress+3*4096-1,&pa));
    assert(pa==neighbor.pa[0]+3*4096-1);
    assert(f.self.r18StdMap(&replacement,0,replacement.getLength(),0,
        nullptr,&replacementCommand,nullptr,&replacementAddress,&replacementLength)==kIOReturnSuccess);
    assert(replacementAddress==wideAddress && f.domain->allocator.livePages==9);
    assert(f.self.r18StdTranslate(replacementAddress+5*4096+61,&pa));
    assert(pa==replacement.pa[0]+5*4096+61);
    assert(f.self.r18StdUnmap(&neighbor,&neighborCommand,neighborAddress,neighborLength)==kIOReturnSuccess);
    assert(f.self.r18StdUnmap(&replacement,&replacementCommand,replacementAddress,replacementLength)==kIOReturnSuccess);
    f.self.r17Export(&f.caller);
    assert(f.domain->snapshot.maxMappedPages==16);
    assert(f.domain->snapshot.peakPages==19 && f.domain->snapshot.reusedAllocations==1);
    assert(f.domain->snapshot.records[0].count==16);
    assert(f.domain->snapshot.mapsTotal==3 && f.domain->snapshot.retiresTotal==3);
    assert(f.caller.completionSequence==6 && f.caller.completed==6);
    std::puts("production mapper: 16 physical runs, variable allocation, live neighbor and reuse PASS");
}

int main() {
    static_assert(amdtx::kSlots==16 && amdtx::kPages==256 && amdtx::kMapPages==32,
                  "Round32 bounded dynamic geometry");
    static_assert(r27rx::kIovaBase==amdtx::kBase+512*4096ULL,
                  "RX uses independent L1 tables");
    productionCapacityProbe();
    normalVariableMappings();
}
'''


def harness():
    header = (ROOT / 'kext/AMDMapperProbeInternal.hpp').read_text(encoding='utf-8')
    tx = (ROOT / 'kext/AMDMapperProbeTxDebug.cpp').read_text(encoding='utf-8')
    names = ['M23_CMD_BUF_SIZE', 'M2B2_CMD_LOG_MAX', 'M2B2_CMD_COMPL_WAIT',
             'M2B2_OFF_CMD_HEAD', 'M2B2_OFF_CMD_TAIL', 'M2B2_CMD_INV_IOMMU_PAGES',
             'M2B2_CMD_PDE_MASK', 'M2B2_CMD_ALL_PAGES_ADDR', 'M2B2_IDENTITY_LIMIT']
    constants = '\n'.join(re.search(r'^#define\s+' + name + r'\s+\S+', header, re.M).group(0)
                          for name in names)
    prefix = host.PREFIX
    begin = prefix.index('class IOMemoryDescriptor {')
    end = prefix.index('struct IODMAMapSpecification {}')
    prefix = prefix[:begin] + IOKIT + prefix[end:]
    mmio = host.MMIO.replace('    void publishStdStats() {}', '''
    bool r18StdReady() const;
    bool r18StdOwnsAddress(uint64_t) const;
    bool r18StdTranslate(uint64_t, uint64_t *) const;
    bool r32CapacityProbe();
    void publishStdStats() {}''')
    text = prefix + constants + '\n#define M2B1_LOOP_TIMEOUT 32\n'
    text += host.section(header, 'struct LayoutRun {', '// ---- kNicPaths')
    text += host.section(header, 'struct M2B2CmdRecord {', '// ---- m2b2ResetEventLog')
    text += mmio + DMA_ADAPTER
    text += host.section(header, 'static inline void m2b2WriteCmd(', '// ---- m2b2InvAddress')
    text += host.section(header, 'static inline UInt64 m2b2InvAddress()', '// ---- M2B2 measurement')
    text += host.section(header, 'static inline bool m2b2Submit(', '// ---- m2b2ReadBar64')
    text += host.section(tx, 'struct org_maz1_AMDMapperProbe::R17Domain {',
                         '// The pool owns mbufs;')
    text += host.section(tx, 'static const UInt32 kNoSlot',
                         'IOReturn org_maz1_AMDMapperProbe::r17Callback(')
    text += host.section(tx, 'void org_maz1_AMDMapperProbe::r17SyncCommand(',
                         'void org_maz1_AMDMapperProbe::r17PublishWindow(')
    text += host.section(tx, 'void org_maz1_AMDMapperProbe::r17Export(',
                         'void org_maz1_AMDMapperProbe::r17Release(')
    text += host.section(tx, 'static inline UInt64 r18LeafFor(',
                         '// ================= Round28:')
    return text + TESTS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', default=shutil.which('g++') or shutil.which('clang++'))
    parser.add_argument('--emit', type=Path)
    parser.add_argument('--sanitize', action='store_true')
    args = parser.parse_args()
    source = harness()
    if args.emit:
        args.emit.write_text(source, encoding='utf-8')
        return
    if not args.compiler:
        parser.error('No host C++ compiler found; use --compiler or --emit')
    with tempfile.TemporaryDirectory(prefix='r32-mapper-') as directory:
        cpp = Path(directory) / 'mapper.cpp'
        binary = Path(directory) / 'mapper-test'
        cpp.write_text(source, encoding='utf-8')
        command = shlex.split(args.compiler) + ['-std=c++11', '-Wall', '-Wextra', '-Werror',
                   '-I', str(ROOT), str(cpp), '-o', str(binary)]
        if args.sanitize:
            command += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-g']
        subprocess.run(command, check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == '__main__':
    main()
