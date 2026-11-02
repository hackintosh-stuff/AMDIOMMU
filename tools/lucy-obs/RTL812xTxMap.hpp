#ifndef RTL812X_TX_MAP_HPP
#define RTL812X_TX_MAP_HPP
#include <stdint.h>
/* Kernel-only, same address space ABI. Include IOReturn/IOService first.
 * Driver NEVER discovers probe. Probe explicitly installs on matching device.
 * callback/context remain valid until successful kDetach. owner is retained.
 * Map runs on output thread: bounded polling, no sleep/no driver reentry.
 * Retire runs ONLY from dedicated workloop timer; may bounded-poll commands.
 * Completion only release-publishes Pending; never callback/free/wait.
 */
namespace r16tx {
static const char kFunctionName[] = "RTL812xTxMapConfigure-v1";
static const uint32_t kVersion = 1, kMaxSegments = 8, kMaxPages = 16;
static const uint64_t kMaxBytes = 65536;
enum { kInstall = 1, kDisarm = 2, kQuery = 3, kDetach = 4 };
enum { kMap = 1, kRetire = 2 };
enum { kIdle = 0, kMapping = 1, kSubmitted = 2, kPending = 3,
       kRetiring = 4, kControl = 5 };
struct Segment { uint64_t address, length; };
struct Request {
    uint32_t version, bytes, bdf, token, reqId, count;
    uint64_t handle; // Map input=0. Any nonzero output owns a cleanup obligation.
    uint64_t tMap, tDone, tRetire; // mach ticks, backend stamps map/retire
    // Actual DMA backing. Driver mode property distinguishes native mbuf from
    // page-aligned real-TX staging; staging copies the entire selected frame.
    Segment physical[kMaxSegments];
    Segment iova[kMaxSegments]; // Map returns SAME count/order/length/offset
};
typedef IOReturn (*Callback)(void *context, uint32_t op, Request *request);
struct Configure {
    uint32_t version, bytes, op, bdf, token, state;
    uint64_t deadline; // mach absolute ticks, finite >now; no new Map after it
    Callback callback;
    void *context;
    IOService *owner; // retained by driver until successful Detach (not Disarm)
    uint64_t handle; // Reserved output (0); Busy => MUST NOT restore DTE/unload.
    uint32_t mapped, completed, retired, dropped;
};
struct Descriptor { uint64_t address, length; uint32_t opts1, opts2; };
struct Witness {
    Request request;
    uint64_t tOwn, tFree;
    uint32_t cumulative, firstSlot, lastSlot, retired;
    uint32_t doneClose, closeMask; // actual close register sample + modulo mask
    Descriptor descriptors[kMaxSegments];
};
struct Snapshot {
    uint32_t magic, version, bytes, count; // magic=0x36315854 (TX16 LE)
    uint32_t bdf, token, dropped, state;
    uint64_t tPublished;
    Witness witnesses[4]; // committed only after successful Retire
};
/* Install only Idle/uninstalled/non-VTD and matching BDF/nonzero token.
 * One installation per driver start. Detach keeps token filter (DROP forever),
 * state allocation and a harmless timer until stop; no callback after Detach.
 * All selected token req1..4 use mapping or DROP, NEVER identity fallback.
 * Map success requires nonzero handle + valid IOVAs + all invalidations done.
 * Map failure with handle=0 GUARANTEES no translations/commands remain live.
 * Map failure/invalid reply with handle!=0: driver pins m, queues Retire.
 * Retire failures preserve handle/m and retry; success guarantees invalidation
 * complete and IOVA safe to reuse. Backend may not clear handle on failure.
 * Driver retains up to 4 retired mbufs until Detach as PA-reuse quarantine.
 * Staging mode additionally retains four prepared, aligned 4KiB DMA buffers;
 * physical[] names these actual buffers, not the original mbuf cursor PAs.
 * Detach complete failure pins resources/owner. tFree follows both DMA buffer
 * complete/release and original mbuf free; successful Retire alone never frees.
 * Disarm stops new Map and returns Busy until submitted/pending work drains.
 * Query does not callback. Detach only after Disarm+Idle: frees quarantine,
 * clears callback/context and releases owner. MUST succeed before DTE restore.
 * Reset/stop without real close-pointer completion pins outstanding m/owner
 * (intentional fail-closed leak, not fabricated completion or early free).
 */
}
#endif
