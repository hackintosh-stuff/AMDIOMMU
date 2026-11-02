#!/usr/bin/env python3
"""Run the production Round31 worker, stop RPC, wait and stop() on host stubs.

Only the normal lifecycle is exercised: a 125 s logical active interval, explicit
stop/restore, and service stop joining a retained worker with its gate open.
Time and hardware are stubbed; the actual kernel entry points and event-window
function are extracted and compiled, not reimplemented as a parallel model.
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


PREFIX = r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
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
static UInt64 tick = 1;
static UInt64 mach_absolute_time() { return ++tick; }
static std::function<void(unsigned)> sleepHook;
static void IOSleep(unsigned ms) { tick += UInt64(ms) * 1000000; sleepHook(ms); }
struct OSObject {
    int refs = 1;
    virtual ~OSObject() = default;
    void retain() { ++refs; }
    void release() { assert(refs > 0); --refs; }
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
    void removeProperty(const char *) { removed = true; }
    void disable() { disabled = true; }
    IOReturn setProperties(OSObject *) { return kIOReturnUnsupported; }
    void stop(IOService *) { baseStopped = true; }
};
using IOMapper = IOService;
#define super IOMapper
static void setHexProperty(IOService *self, const char *key, UInt64 value) {
    self->numbers[key] = value;
}
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
    removed = true; timer->loop = nullptr;
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
class org_example_AMDMapperProbe : public IOMapper {
public:
    bool fR31Session=true, fR31SessionCompleted=false;
    volatile UInt32 fR31StopRequested=0, fR31WorkerActive=0;
    volatile UInt64 fR31StopRequestTime=0;
    R27ProbeTimer *fM22b2Timer=nullptr;
    bool fMapWindowOpen=true, fArmed=true;
    IOService *fPublishNotifier=nullptr, *fNicDevice=nullptr, *fTarget=nullptr;
    IOWorkLoop *loop=nullptr;
    unsigned runs=0;
    bool resourcesAlive=false, postSampled=false;
    UInt64 restoreTime=0;
    IOWorkLoop *getWorkLoop() { return loop; }
    static void m22b2TimerFired(OSObject *, IOTimerEventSource *);
    static void r31SessionWorker(void *, wait_result_t);
    void r31RequestStop();
    IOReturn setProperties(OSObject *);
    void stop(IOService *);
    void runM22b2PageTableProbe();
    static const unsigned kM22b2RawKeep=16;
WINDOW_STRUCT;
    M22b2EventWindow window{};
};
static UInt64 m2b2NowNS() { return mach_absolute_time(); }
static UInt64 m2b2WallSecs() { return tick / 1000000000; }
static UInt64 m2b2ToMS(UInt64 ticks) { return ticks / 1000000; }
static UInt64 mmioRead64(volatile UInt8 *, UInt32) { return 0; }
static UInt32 mmioRead32(volatile UInt8 *, UInt32) { return 1u << 3; }
static void mmioWrite64(volatile UInt8 *, UInt32, UInt64) {}
static void m2b2DoPostSample(void *p) {
    auto *self=static_cast<org_example_AMDMapperProbe *>(p);
    assert(self->fR31StopRequested && self->resourcesAlive);
    self->postSampled=true;
}
'''

SUFFIX = r'''
void org_example_AMDMapperProbe::runM22b2PageTableProbe() {
    ++runs;
    assert(refs == 2 && !loop->inGate());
    assert(fArmed && fMapWindowOpen && fTarget && !fTarget->removed);
    resourcesAlive=true;
    struct Resources {
        org_example_AMDMapperProbe *self;
        ~Resources() { self->resourcesAlive=false; }
    } resources{this};
    volatile UInt8 *base=nullptr;
    volatile UInt32 *evtBuf=nullptr;
    const UInt32 tgt=0x300;
    auto &winMain=window;
    bool mainWindowRan=false, postSampleDone=true;
    // The real call takes &postSample. Use a one-pointer shim for its callback.
    struct Post { org_example_AMDMapperProbe *self; } postSample{this};
    const char *firstFailStage=nullptr;
    struct { bool failed=false; } ctx;
MAIN_WINDOW
    assert(mainWindowRan && postSampled && resourcesAlive);
    assert(fArmed && fMapWindowOpen && fTarget && !fTarget->removed);
    setProperty("m2-3l-session-state", "draining");
    // Hardware RX/R29D/TX/restore are stubbed here; the worker must publish
    // stopped/end only after this function and its local resources complete.
    restoreTime=mach_absolute_time();
SESSION_COMPLETE
}
int main() {
    using Probe=org_example_AMDMapperProbe;
    for (bool serviceStop : {false, true}) {
        Probe p; IOWorkLoop loop; R27ProbeTimer timer(&loop);
        IOService nic, target, notifier;
        p.loop=&loop; p.fM22b2Timer=&timer;
        p.fNicDevice=&nic; p.fTarget=&target; p.fPublishNotifier=&notifier;
        p.setProperty("m2-3l-session-state", "preparing");
        loop.gated=true;
        Probe::m22b2TimerFired(&p, &timer);
        assert(p.runs == 0 && p.fR31WorkerActive && p.refs == 2 && queued);
        assert(threadRefsReleased == (serviceStop ? 2u : 1u));
        const UInt64 started=tick;
        UInt64 rpcBefore=0, rpcAfter=0;
        if (!serviceStop) {
            loop.gated=false; // timer callback has returned
            sleepHook=[&](unsigned ms) {
                assert(ms == 100 && p.resourcesAlive && p.fR31WorkerActive);
                assert(!loop.inGate() && p.fArmed && !target.removed);
                assert(p.strings["m2-3l-session-state"] == "active");
                if (tick-started >= 125000000000ULL) {
                    OSDictionary stop;
                    rpcBefore=mach_absolute_time();
                    assert(p.setProperties(&stop) == kIOReturnSuccess);
                    rpcAfter=mach_absolute_time();
                    assert(p.resourcesAlive && p.runs == 1);
                    assert(p.strings["m2-3l-session-state"] == "active");
                }
            };
            dispatchWorker();
            assert(p.window.durMS >= 125000 && p.window.valid);
            assert(p.numbers["m2-3l-stop-request-time"] > rpcBefore);
            assert(p.numbers["m2-3l-stop-request-time"] < rpcAfter);
            p.stop(nullptr);
            assert(!loop.inGate());
        } else {
            // A normal service stop entered with the probe gate held. The
            // actual stop() must open it and keep every dependency until join.
            sleepHook=[&](unsigned ms) {
                assert(ms == 10 && !loop.inGate());
                assert(timer.cancelled && !loop.removed);
                assert(p.fArmed && p.fTarget == &target && !target.removed);
                dispatchWorker();
            };
            p.stop(nullptr);
            assert(loop.inGate()); // caller's original gate state restored
        }
        assert(p.runs == 1 && p.refs == 1 && !p.fR31WorkerActive);
        assert(!p.resourcesAlive && p.fR31SessionCompleted && p.postSampled);
        assert(p.strings["m2-3l-session-state"] == "stopped");
        assert(p.numbers["m2-3l-session-end"] > p.restoreTime);
        const std::vector<std::string> expected{
            "preparing", "active", "stop-requested", "draining", "stopped"};
        assert(p.states == expected);
        assert(loop.removed && timer.refs == 0 && !p.fM22b2Timer);
        assert(!p.fArmed && !p.fMapWindowOpen && p.baseStopped);
        assert(target.removed && nic.removed && notifier.disabled);
        assert(!p.fTarget && !p.fNicDevice && !p.fPublishNotifier);
    }
    assert(threadEnds == 2 && threadRefsReleased == 2);
    std::puts("PASS: production worker/RPC/window/stop; 125s logical active time; restore before dependency release");
}
'''


def main():
    entry = (ROOT / 'kext/AMDMapperProbe.cpp').read_text()
    pgt = (ROOT / 'kext/AMDMapperProbePgt.cpp').read_text()
    internal = (ROOT / 'kext/AMDMapperProbeInternal.hpp').read_text()
    header = (ROOT / 'kext/AMDMapperProbe.hpp').read_text()
    window_struct = body(header, '    struct M22b2EventWindow {')
    constants = '\n'.join(re.findall(
        r'^#define M2B2_(?:EVT_BUFFER_SIZE|EVENT_TYPE_SHIFT|EVENT_TYPE_MASK|'
        r'EVENT_DEVID_MASK|OFF_EVT_HEAD|OFF_EVT_TAIL|OFF_STATUS|'
        r'STATUS_EVT_OVERFLOW|STATUS_EVT_RUN|MAIN_MEAS_SECS)\s+[^\n]+', internal, re.M))
    methods = [body(entry, 'void org_example_AMDMapperProbe::r31RequestStop('),
               body(entry, 'IOReturn org_example_AMDMapperProbe::setProperties('),
               body(entry, 'void org_example_AMDMapperProbe::stop('),
               body(pgt, 'void org_example_AMDMapperProbe::m22b2TimerFired('),
               body(pgt, 'void org_example_AMDMapperProbe::r31SessionWorker('),
               body(internal, 'static inline void r31WaitForSessionStop('),
               body(internal, 'static inline void m2b2SampleEvents(')]
    start = pgt.index('    if (fR31Session) {\n        setHexProperty(this, "m2-3l-session-start"')
    end = pgt.index('    // 【第九轮】把窗口边界', start)
    window = pgt[start:end]
    complete = body(pgt, '        if (fR31Session) {\n            fR31SessionCompleted =')
    assert pgt.index('r27RxReady();') < start
    assert pgt.index('r17ResumeOutput();') < pgt.index(complete)
    assert 'fR31Session ? &fR31StopRequested : nullptr' in window
    # Adjust only the hardware-specific post-sample callback's host argument.
    prefix = PREFIX.replace('WINDOW_STRUCT', window_struct)
    prefix = prefix.replace('static_cast<org_example_AMDMapperProbe *>(p);\n    assert(self->',
                            '*static_cast<org_example_AMDMapperProbe **>(p);\n    assert(self->')
    source = constants + '\n' + prefix + '\n' + '\n\n'.join(methods) + '\n'
    source += SUFFIX.replace('MAIN_WINDOW', window).replace('SESSION_COMPLETE', complete)
    compiler = shlex.split(os.environ.get('CXX', ''))
    if not compiler:
        compiler = [shutil.which('clang++') or shutil.which('g++') or 'c++']
    with tempfile.TemporaryDirectory(prefix='r31-session-') as tmp:
        cpp, exe = Path(tmp) / 'session.cpp', Path(tmp) / 'session'
        cpp.write_text(source)
        subprocess.run(compiler + ['-std=c++17', '-Wall', '-Wextra', '-Werror',
                                  str(cpp), '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True)


if __name__ == '__main__':
    main()
