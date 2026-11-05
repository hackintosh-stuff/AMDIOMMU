#!/usr/bin/env python3
"""Compile the production service-domain lifecycle against host hardware stubs.

One normal cycle: setup returns, the domain/driver survive 125 logical seconds,
R31Stop queues teardown, and stop() joins it with its gate open. Native stop
drains TX before local RX recovery and needs no peer tail. The real context,
capture/handoff, workers, event endpoints, RX/TX recovery ordering, register
restore/readback and resource-release blocks are compiled. Hardware setup and
the historical evidence-analysis blocks are omitted; this is not a macOS kext
build or a NIC/DMA emulation.
"""
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def body(source, start):
    begin = source.index(start)
    opening = source.index('{', begin)
    depth = 0
    for end in range(opening, len(source)):
        depth += (source[end] == '{') - (source[end] == '}')
        if depth == 0:
            return source[begin:end + 1]
    raise AssertionError('unterminated production body: ' + start)


def section(source, start, end):
    begin = source.index(start)
    return source[begin:source.index(end, begin)]


PREFIX = r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <map>
#include <string>
#include <vector>
using UInt8 = uint8_t;
using UInt32 = uint32_t;
using UInt64 = uint64_t;
using IOReturn = int;
using wait_result_t = int;
using kern_return_t = int;
using thread_t = void *;
using thread_continue_t = void (*)(void *, wait_result_t);
constexpr thread_t THREAD_NULL = nullptr;
enum { KERN_SUCCESS=0, kIOReturnSuccess=0, kIOReturnBadArgument=1,
       kIOReturnNotReady=2, kIOReturnUnsupported=3 };
static UInt64 tick = 1, restoredAt = 0;
static std::vector<std::string> lifecycle;
static UInt64 mach_absolute_time() { return ++tick; }
static std::function<void(unsigned)> sleepHook;
static void IOSleep(unsigned ms) {
    tick += UInt64(ms) * 1000000;
    if (sleepHook) sleepHook(ms);
}
static std::map<void *, size_t> allocations;
static void *IOMalloc(size_t bytes) {
    void *p=std::malloc(bytes); assert(p); allocations[p]=bytes; return p;
}
static void IOFree(void *p, size_t bytes) {
    assert(restoredAt && allocations.at(p) == bytes);
    allocations.erase(p); lifecycle.emplace_back("context-release"); std::free(p);
}
static void hostBzero(void *p, size_t bytes) { std::memset(p, 0, bytes); }
#define bzero hostBzero
struct OSObject {
    int refs = 1;
    const char *tag = nullptr;
    bool releaseAfterRestore = false;
    virtual ~OSObject() = default;
    void retain() { ++refs; }
    void release() {
        assert(refs > 0);
        if (releaseAfterRestore) assert(restoredAt);
        if (tag) lifecycle.emplace_back(tag);
        --refs;
    }
};
struct OSBoolean : OSObject {} trueValue;
static OSObject *kOSBooleanTrue = &trueValue;
struct OSDictionary : OSObject {
    OSObject *getObject(const char *key) {
        return std::string(key) == "R31Stop" ? kOSBooleanTrue : nullptr;
    }
};
#define OSDynamicCast(type, value) dynamic_cast<type *>(value)
struct IOService : OSObject {
    std::map<std::string, std::string> strings;
    std::map<std::string, UInt64> numbers;
    std::vector<std::string> states;
    bool removed = false, disabled = false, baseStopped = false;
    void setProperty(const char *key, const char *value) {
        strings[key] = value;
        if (std::string(key) == "m2-3l-session-state") states.emplace_back(value);
    }
    void removeProperty(const char *) { assert(restoredAt); removed = true; }
    void disable() { assert(restoredAt); disabled = true; }
    IOReturn setProperties(OSObject *) { return kIOReturnUnsupported; }
    void stop(IOService *) { baseStopped = true; }
};
using IOMapper = IOService;
#define super IOMapper
static void setHexProperty(IOService *self, const char *key, UInt64 value) {
    self->numbers[key] = value;
}
struct IOMemoryDescriptor : OSObject {};
struct IOBufferMemoryDescriptor : IOMemoryDescriptor {};
struct IOMemoryMap : OSObject {};
struct R27ProbeTimer;
struct IOWorkLoop {
    bool gated = false, removed = false;
    bool inGate() const { return gated; }
    void removeEventSource(R27ProbeTimer *);
};
struct IOTimerEventSource : OSObject {};
struct R27ProbeTimer : IOTimerEventSource {
    IOWorkLoop *loop;
    bool cancelled = false;
    explicit R27ProbeTimer(IOWorkLoop *w) : loop(w) {}
    IOWorkLoop *getWorkLoop() { return loop; }
    void cancelTimeout() { assert(loop && loop->gated); cancelled = true; }
    void openClientGate() { assert(loop && loop->gated); loop->gated = false; }
    void closeClientGate() { assert(loop && !loop->gated); loop->gated = true; }
};
void IOWorkLoop::removeEventSource(R27ProbeTimer *timer) {
    assert(restoredAt); removed = true; timer->loop = nullptr;
}
static thread_continue_t queued = nullptr;
static void *queuedParameter = nullptr;
static unsigned threadRefsReleased = 0, threadEnds = 0;
static kern_return_t kernel_thread_start(thread_continue_t fn, void *p,
                                         thread_t *thread) {
    assert(!queued); queued=fn; queuedParameter=p; *thread=p; return KERN_SUCCESS;
}
static void thread_deallocate(thread_t t) { assert(t); ++threadRefsReleased; }
static thread_t current_thread() { return &trueValue; }
static kern_return_t thread_terminate(thread_t t) {
    assert(t); ++threadEnds; return KERN_SUCCESS;
}
static void dispatchWorker() {
    auto fn=queued; auto p=queuedParameter; queued=nullptr; queuedParameter=nullptr;
    assert(fn); fn(p, 0);
}
namespace r15pool {
enum { kDisarmed=1, kActive=2 };
struct Request { UInt32 poolId; struct { UInt32 state; } out; };
}
namespace r20tx { enum { kStageExit=3 }; }
COMMAND_STRUCTS
class org_example_AMDMapperProbe : public IOMapper {
public:
    // This existing fixture exercises the legacy session branch.
    bool fR44Auto=false;
    void r44PublishMappings() { assert(false); }
    bool r44StopAuto() { assert(false); return false; }
    struct R33DeviceDomain;
    bool fR31Session=true, fR31SessionCompleted=false;
    volatile UInt32 fR31StopRequested=0, fR31WorkerActive=0;
    volatile UInt64 fR31StopRequestTime=0;
    R33DeviceDomain *fR33Domain=nullptr;
    volatile UInt32 fR33TeardownState=0;
    UInt32 fR33InstallCount=0;
    R27ProbeTimer *fM22b2Timer=nullptr;
    bool fMapWindowOpen=true, fArmed=true;
    IOService *fPublishNotifier=nullptr, *fNicDevice=nullptr, *fTarget=nullptr;
    IOService *fR15Service=nullptr, *driver=nullptr;
    r15pool::Request fR15Request{};
    UInt32 fR15PoolRpcCalls=0;
    UInt64 fR15MapTicks=0, fR15InvTicks=0;
    void *fR34Rx=nullptr;
    bool nativeRxResumed=false;
    IOWorkLoop *loop=nullptr;
    unsigned runs=0;
    bool rxDrained=false, tailDrained=false, txDrained=false;
    bool detached=false, resumed=false, backendReleased=false;
    IOBufferMemoryDescriptor memory[5];
    IOMemoryDescriptor descriptor;
    IOMemoryMap mapping, postMapping;
    UInt8 fakeMMIO=0;
    UInt32 commands[16]{}, events[4]{};
    UInt64 tables[1024]{}, deviceTable[4]{}, semaphore=0;
    struct {
        UInt64 tWinStart=0, tWinEnd=0, tRecoveryStart=0, tTranslateOff=0;
    } fM22b2Dma;
    IOWorkLoop *getWorkLoop() { return loop; }
    static void m22b2TimerFired(OSObject *, IOTimerEventSource *);
    static void r31SessionWorker(void *, wait_result_t);
    static void r33DomainStopWorker(void *, wait_result_t);
    void r31RequestStop();
    void r33ScheduleDomainStop();
    bool r33DomainStopPending() const;
    IOReturn setProperties(OSObject *);
    void stop(IOService *);
    void runM22b2PageTableProbe();
    void finishM22b2PageTableProbe(R33DeviceDomain *, bool);
    void m2b2R15Finish();
    void m2b2R15Release();
R15_SCOPE;
    static const unsigned kM22b2RawKeep=16;
WINDOW_STRUCT;
    M22b2EventWindow fM22b2WinPre{}, fM22b2WinMain{};
    bool resourcesAlive() const {
        for (const auto &m : memory) if (m.refs != 1) return false;
        return descriptor.refs == 1 && mapping.refs == 1;
    }
    bool r27RxFinish(unsigned timeout) {
        assert(timeout == 15000 && resourcesAlive() && !restoredAt);
        assert(fR15Service == driver && driver->refs == 2);
        assert(!rxDrained && !tailDrained);
        assert(fR31Session ? txDrained : !txDrained);
        rxDrained=true; lifecycle.emplace_back("rx-drain"); return true;
    }
    bool r29WaitTailDone(unsigned timeout) {
        assert(!fR31Session && timeout == 5000 && rxDrained &&
               !tailDrained && !txDrained && !restoredAt);
        tailDrained=true; lifecycle.emplace_back("tail-drain"); return true;
    }
    bool r17Installed() const { return true; }
    bool r17StopSubmit(unsigned timeout, const char *) {
        assert(timeout == 2000 && !txDrained && !restoredAt);
        assert(fR31Session ? (!rxDrained && !tailDrained) :
                            (rxDrained && tailDrained));
        txDrained=true; lifecycle.emplace_back("tx-drain"); return true;
    }
    void r17SampleExit(unsigned) {
        assert(txDrained && !restoredAt);
        assert(fR31Session ? !rxDrained : tailDrained);
        lifecycle.emplace_back("tx-exit-sample");
    }
    void r17SetTranslateOff(UInt64 when) {
        assert(txDrained && rxDrained && resourcesAlive());
        assert(fR31Session ? !tailDrained : tailDrained);
        restoredAt=when; lifecycle.emplace_back("restore");
    }
    bool r17Detach() {
        assert(restoredAt && resourcesAlive());
        assert(!fR31Session || nativeRxResumed);
        detached=true; lifecycle.emplace_back("detach"); return true;
    }
    bool r17ResumeOutput() {
        assert(detached && resourcesAlive());
        resumed=true; lifecycle.emplace_back("resume"); return true;
    }
    bool r34RxResumePhysical() {
        if (!fR34Rx || nativeRxResumed) return true;
        assert(restoredAt && rxDrained && resourcesAlive());
        assert(txDrained && !tailDrained && !detached && !resumed);
        nativeRxResumed=true; lifecycle.emplace_back("rx-resume"); return true;
    }
    void r34RxRelease() {
        assert(nativeRxResumed); fR34Rx=nullptr;
    }
    void r17Export(void *) {}
    void r17Release() { assert(resumed); r34RxRelease(); backendReleased=true; }
};
DOMAIN_STRUCT;
static UInt64 m2b2NowNS() { return mach_absolute_time(); }
static UInt64 m2b2WallSecs() { return tick / 1000000000; }
static UInt64 m2b2ToMS(UInt64 ticks) { return ticks / 1000000; }
static std::map<UInt32, UInt64> registers;
static UInt64 mmioRead64(volatile UInt8 *base, UInt32 off) {
    assert(base); return registers[off];
}
static UInt32 mmioRead32(volatile UInt8 *base, UInt32 off) {
    assert(base && off == M2B2_OFF_STATUS);
    const auto control=registers[M2B2_OFF_CONTROL];
    return ((control & M2B2_CTRL_EVT_LOG_EN) ? M2B2_STATUS_EVT_RUN : 0) |
           ((control & M2B2_CTRL_CMDBUF_EN) ? M2B2_STATUS_CMDBUF_RUN : 0);
}
static void mmioWrite64(volatile UInt8 *base, UInt32 off, UInt64 value) {
    assert(base); registers[off]=value;
}
static void OSSynchronizeIO() {}
static void m2b2DoPostSample(void *p) {
    auto *sample=static_cast<M2b2PostSample *>(p);
    assert(sample && sample->haveBar && sample->bar);
    assert(!restoredAt); sample->tClo=m2b2NowNS(); sample->tTail=m2b2NowNS();
    sample->cloOk=sample->tailOk=true; lifecycle.emplace_back("post-sample");
}
void org_example_AMDMapperProbe::m2b2R15Finish() {
    assert(backendReleased && restoredAt && resourcesAlive());
    if (fR31Session) return;
    fR15Request.out.state=r15pool::kDisarmed;
    lifecycle.emplace_back("pool-disarm");
}
'''

SETUP = r'''
void org_example_AMDMapperProbe::runM22b2PageTableProbe() {
    ++runs;
    assert(refs == 2 && !loop->inGate());
    assert(fArmed && fMapWindowOpen && fTarget && !fTarget->removed);
SETUP_OWNERS
    // Hardware setup is a fixture; all captures and owner transfers below are
    // production code. Independent object identities make stale copies visible.
DOMAIN_LOCALS
    (void)resourcesReleased;
    ptMem=&memory[0]; tbl=&memory[1]; cmdBufMd=&memory[2];
    semMd=&memory[3]; evtMd=&memory[4]; md=&descriptor;
    map=&mapping; postMap=&postMapping;
    base=&fakeMMIO; pt=tables; dte=deviceTable; root=tables; l2=tables+512;
    sem=&semaphore; evtBuf=events;
    ptPA=0x100000; tblPA=0x200000; cmdPA=0x300000; semPA=0x400000;
    evtPA=0x500000; rootPA=ptPA; l2PA=ptPA+4096; ptBytes=8192;
    ptPageCount=2; tgt=0x300;
    origDT=0xa000; origCmd=0xb000; origEvt=0xc000; origCtrl=0x100;
    preWindowRan=evtResetOk=invAllOk=invDevOk=invPagesOk=true;
    ctx.buf=commands; ctx.sem=sem; ctx.rootPA=rootPA;
    ctx.completionSequence=129; ctx.idx=7; ctx.tail=128; ctx.completed=129;
    postSampleDone=true; postSample.bar=&fakeMMIO; postSample.haveBar=true;
    fR15Service=driver; driver->retain();
    fR34Rx=driver; // Native RX borrows the ordinary ring; no R15 pool exists.
    registers[M2B2_OFF_DEV_TABLE]=tblPA;
    registers[M2B2_OFF_CMD_BUF]=cmdPA;
    registers[M2B2_OFF_EVT_BUF]=evtPA;
    registers[M2B2_OFF_CONTROL]=origCtrl | M2B2_CTRL_IOMMU_EN |
        M2B2_CTRL_CMDBUF_EN | M2B2_CTRL_EVT_LOG_EN;
    auto &winMain=fM22b2WinMain;
SAVE_DOMAIN;
SETUP_HANDOFF
}
'''

FINISH = r'''
void org_example_AMDMapperProbe::finishM22b2PageTableProbe(
    R33DeviceDomain *domain, bool finishWindow) {
    assert(domain && allocations.count(domain));
    assert(fR15Service == driver && driver->refs == 2 && resourcesAlive());
    assert(domain->ctx.completionSequence == 129 && domain->ctx.idx == 7);
    assert(domain->ctx.buf == commands && domain->ctx.sem == &semaphore);
    assert(domain->postMap == &postMapping && domain->pt == tables);
FINISH_ALIASES
    // The omitted historical diagnostics use these aliases. Compile all of
    // them anyway, including their exact production types and member names.
USE_ALIASES
FINISH_WINDOW
RECOVER
RESOURCE_RELEASE
}
'''

TEST = r'''
int main() {
    using Probe=org_example_AMDMapperProbe;
    Probe p; IOWorkLoop loop; R27ProbeTimer timer(&loop);
    IOService nic, target, notifier, driver;
    p.loop=&loop; p.fM22b2Timer=&timer; p.driver=&driver;
    p.fNicDevice=&nic; p.fTarget=&target; p.fPublishNotifier=&notifier;
    for (auto &m : p.memory) { m.tag="memory-release"; m.releaseAfterRestore=true; }
    p.mapping.tag="mapping-release"; p.mapping.releaseAfterRestore=true;
    p.descriptor.tag="descriptor-release"; p.descriptor.releaseAfterRestore=true;
    driver.tag="driver-release"; driver.releaseAfterRestore=true;
    p.postMapping.tag="post-map-release";
    p.setProperty("m2-3l-session-state", "preparing");
    loop.gated=true;
    Probe::m22b2TimerFired(&p, &timer);
    assert(p.runs == 0 && p.fR31WorkerActive && p.refs == 2 && queued);
    loop.gated=false; // timer callback returns before the setup worker runs
    dispatchWorker();
    assert(threadEnds == 1 && threadRefsReleased == 1 && !queued);
    assert(p.runs == 1 && p.refs == 1 && !p.fR31WorkerActive);
    assert(p.fR33Domain && p.resourcesAlive() && allocations.size() == 1);
    assert(p.fR15Service == &driver && driver.refs == 2);
    assert(p.fR34Rx == &driver && !p.fR15Request.poolId);
    assert(lifecycle.empty() && !p.fR31SessionCompleted);
    assert(p.numbers["m2-3n-setup-worker-exit-time"] >
           p.numbers["m2-3l-session-start"]);
    assert(p.numbers["m2-3n-setup-worker-active"] == 0);
    assert(p.numbers["m2-3n-install-count"] == 1);
    auto *domain=p.fR33Domain;
    const UInt64 started=tick;
    // Logical idle/traffic intervals pass with no session worker kept alive.
    // Neither domain identity nor the driver/native RX context may change.
    for (unsigned ms : {40000u, 45000u, 40000u}) {
        IOSleep(ms);
        assert(!queued && !p.fR31WorkerActive && p.refs == 1);
        assert(p.fR33Domain == domain && allocations.size() == 1);
        assert(domain->rootPA == 0x100000 && domain->tblPA == 0x200000);
        assert(domain->ctx.completionSequence == 129 && p.resourcesAlive());
        assert(p.fR15Service == &driver && driver.refs == 2);
        assert(p.fR34Rx == &driver && !p.fR15Request.poolId);
        assert(p.strings["m2-3l-session-state"] == "active");
        assert(p.strings["m2-3n-domain-state"] == "active");
        assert(lifecycle.empty());
    }
    assert(tick-started >= 125000000000ULL);
    OSDictionary request;
    const UInt64 rpcBefore=mach_absolute_time();
    assert(p.setProperties(&request) == kIOReturnSuccess);
    const UInt64 rpcAfter=mach_absolute_time();
    assert(queued && p.fR31WorkerActive && p.fR33TeardownState == 1);
    assert(p.fR33Domain == domain && p.resourcesAlive() && driver.refs == 2);
    assert(!p.fR31SessionCompleted && lifecycle.empty());
    // Service stop joins the already-requested teardown. Dependencies must
    // remain available and the caller's original workloop gate must be opened.
    loop.gated=true;
    sleepHook=[&](unsigned ms) {
        assert(ms == 10 && !loop.inGate() && queued);
        assert(timer.cancelled && !loop.removed);
        assert(p.fArmed && p.fTarget == &target && !target.removed);
        assert(p.fR15Service == &driver && driver.refs == 2);
        dispatchWorker();
    };
    p.stop(nullptr);
    assert(loop.inGate() && threadEnds == 2 && threadRefsReleased == 2);
    assert(p.runs == 1 && p.refs == 1 && !p.fR31WorkerActive && !queued);
    assert(!p.fR33Domain && !p.r33DomainStopPending() && allocations.empty());
    assert(!p.resourcesAlive() && p.fR31SessionCompleted);
    assert(!p.fR15Service && driver.refs == 1);
    assert(p.fM22b2WinMain.durMS >= 125000 && p.fM22b2WinMain.valid);
    assert(p.numbers["m2-3l-stop-request-time"] > rpcBefore);
    assert(p.numbers["m2-3l-stop-request-time"] < rpcAfter);
    assert(p.strings["m2-3l-session-state"] == "stopped");
    assert(p.strings["m2-3n-domain-state"] == "stopped");
    assert(p.numbers["m2-3n-teardown-start"] > rpcAfter);
    assert(p.numbers["m2-3l-session-end"] > restoredAt);
    assert(registers[M2B2_OFF_DEV_TABLE] == 0xa000);
    assert(registers[M2B2_OFF_CMD_BUF] == 0xb000);
    assert(registers[M2B2_OFF_EVT_BUF] == 0xc000);
    assert(registers[M2B2_OFF_CONTROL] == 0x100);
    const std::vector<std::string> expectedStates{
        "preparing", "active", "stop-requested", "draining", "stopped"};
    assert(p.states == expectedStates);
    const std::vector<std::string> expectedLifecycle{
        "post-sample", "post-map-release", "tx-drain", "tx-exit-sample", "rx-drain",
        "restore", "rx-resume", "detach", "resume", "mapping-release",
        "descriptor-release", "memory-release", "memory-release", "memory-release",
        "memory-release", "memory-release", "driver-release", "context-release"};
    assert(lifecycle == expectedLifecycle);
    assert(p.txDrained && p.rxDrained && !p.tailDrained && p.nativeRxResumed);
    assert(loop.removed && timer.refs == 0 && !p.fM22b2Timer);
    assert(!p.fArmed && !p.fMapWindowOpen && p.baseStopped);
    assert(target.removed && nic.removed && notifier.disabled);
    assert(!p.fTarget && !p.fNicDevice && !p.fPublishNotifier);
    std::puts("PASS: production domain handoff/recovery/RPC/stop; setup worker exits; "
              "125s logical ownership; native TX drain/sample precedes local RX recovery "
              "without peer tail; register restore and RX resume precede detach/output "
              "and resource/driver release");
}
'''


def main():
    entry = (ROOT / 'kext/AMDMapperProbe.cpp').read_text()
    pgt = (ROOT / 'kext/AMDMapperProbePgtDebug.cpp').read_text()
    internal = (ROOT / 'kext/AMDMapperProbeInternal.hpp').read_text()
    header = (ROOT / 'kext/AMDMapperProbe.hpp').read_text()
    rxset = (ROOT / 'kext/AMDMapperProbeRxSetDebug.cpp').read_text()
    setup = body(pgt, 'void org_example_AMDMapperProbe::runM22b2PageTableProbe(')
    finish = body(pgt, 'void org_example_AMDMapperProbe::finishM22b2PageTableProbe(')
    domain = body(pgt, 'struct org_example_AMDMapperProbe::R33DeviceDomain {')
    domain_locals = domain[domain.index('{') + 1:domain.rindex('}')]
    # Initialize only fixture locals, while keeping each production field type.
    domain_locals = re.sub(r';', '{};', domain_locals)
    save_domain = body(setup, '    auto saveDomain = [&]()')
    owners = section(setup, '    setProperty("m2-b2-stage", "0-start");',
                     '    // 门控已在 scheduleM22b2()')
    handoff = setup[setup.index('    if (!m2b2BeginEventWindow('):setup.rindex('}')]
    aliases = section(finish, '    auto &winPre =', '    if (!finishWindow)')
    window = section(finish, '    if (!finishWindow)',
                     '    // ---- 第 16b 步：')
    recover = section(finish, 'recover:\n', '    // ---- 第 19 步：')
    release = finish[finish.index('    // ---- 第 20 步：'):finish.rindex('}')]
    alias_names = re.findall(r'auto &(\w+) =', aliases)
    # Every recovery alias must have a capture. The two window objects are
    # service members; resourcesReleased starts false in the context.
    captures = re.findall(r'domain->(\w+) = (\w+);', save_domain)
    assert all(left == right for left, right in captures)
    captured = {left for left, _ in captures}
    assert set(alias_names) - {'winPre', 'winMain'} <= captured
    assert captured == set(re.findall(r'\b(\w+);', domain)) - {'resourcesReleased'}
    assert setup.index('r27RxReady();') < setup.index('    if (!m2b2BeginEventWindow(')
    assert finish.index('r17ResumeOutput();') < finish.index('    // ---- 第 20 步：')
    constants = '\n'.join(re.findall(
        r'^#define (?:M2B1_LOOP_TIMEOUT|M2B2_(?:EVT_BUFFER_SIZE|EVENT_TYPE_SHIFT|'
        r'EVENT_TYPE_MASK|EVENT_DEVID_MASK|OFF_\w+|CTRL_\w+|STATUS_\w+|'
        r'CMD_LOG_MAX|MAIN_MEAS_SECS))\s+[^\n]+', internal, re.M))
    commands = '\n'.join(body(internal, 'struct ' + name + ' {') + ';'
                         for name in ['M2B2CmdRecord', 'M2B2CmdCtx', 'M2b2PostSample'])
    methods = [body(internal, 'static inline bool m2b2BeginEventWindow('),
               body(internal, 'static inline void m2b2EndEventWindow('),
               body(entry, 'void org_example_AMDMapperProbe::r31RequestStop('),
               body(entry, 'IOReturn org_example_AMDMapperProbe::setProperties('),
               body(entry, 'void org_example_AMDMapperProbe::stop('),
               body(pgt, 'void org_example_AMDMapperProbe::m22b2TimerFired('),
               body(pgt, 'void org_example_AMDMapperProbe::r31SessionWorker('),
               body(pgt, 'bool org_example_AMDMapperProbe::r33DomainStopPending('),
               body(pgt, 'void org_example_AMDMapperProbe::r33ScheduleDomainStop('),
               body(pgt, 'void org_example_AMDMapperProbe::r33DomainStopWorker('),
               body(rxset, 'void org_example_AMDMapperProbe::m2b2R15Release(')]
    prefix = PREFIX.replace('COMMAND_STRUCTS', commands).replace('DOMAIN_STRUCT', domain)
    prefix = prefix.replace('WINDOW_STRUCT', body(header, '    struct M22b2EventWindow {'))
    prefix = prefix.replace('R15_SCOPE', body(header, '    struct R15Scope {'))
    setup_test = SETUP.replace('SETUP_OWNERS', owners).replace('DOMAIN_LOCALS', domain_locals)
    setup_test = setup_test.replace('SAVE_DOMAIN', save_domain).replace('SETUP_HANDOFF', handoff)
    finish_test = FINISH.replace('FINISH_ALIASES', aliases)
    finish_test = finish_test.replace('USE_ALIASES', '\n'.join('    (void)' + n + ';' for n in alias_names))
    finish_test = finish_test.replace('FINISH_WINDOW', window).replace('RECOVER', recover)
    finish_test = finish_test.replace('RESOURCE_RELEASE', release)
    source = constants + '\n' + prefix + '\n' + '\n\n'.join(methods) + '\n'
    source += setup_test + finish_test + TEST
    compiler = shlex.split(os.environ.get('CXX', ''))
    if not compiler:
        compiler = [shutil.which('clang++') or shutil.which('g++') or 'c++']
    with tempfile.TemporaryDirectory(prefix='r33-domain-') as tmp:
        cpp, exe = Path(tmp) / 'session.cpp', Path(tmp) / 'session'
        cpp.write_text(source)
        subprocess.run(compiler + ['-std=c++17', '-Wall', '-Wextra', '-Werror',
                                  str(cpp), '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True)


if __name__ == '__main__':
    main()
