#ifndef RTL812X_TX_MAP_NATIVE_HPP
#define RTL812X_TX_MAP_NATIVE_HPP
#include <stdint.h>
/* Round17: native-mbuf TX mapping ABI (kernel-only, same address space).
 *
 * WHAT CHANGED FROM ROUND 16 (RTL812xTxMap.hpp, namespace r16tx)
 * -------------------------------------------------------------
 *  round16 mapped a page-aligned *staging copy*: one 4 KiB DMA buffer per
 *  request, filled with mbuf_copydata(), and flattened to numSegs = 1.
 *  Round17 hands the backend the ACTUAL physical cursor segments of the
 *  packet, keeps their length, order and in-page offset, and lets descriptors
 *  carry the returned non-identity IOVAs. No copy, no second DMA buffer.
 *
 *  Per-request lifetime is now complete: after the hardware completion, the
 *  retire invalidation and the mbuf free, the mapping resources are reusable
 *  and the next request proceeds. Round16 kept four retired mbufs and four
 *  staging buffers until Detach; that coupling (cumulative request count vs
 *  resource lifetime) is gone. What remains finite is *evidence* storage
 *  (kMaxRequests witnesses) and the probe's command budget, not the DMA owner.
 *
 *  A request may therefore return an IOVA whose in-page offset differs from
 *  the previous request's (a native segment's offset is not controllable), and
 *  the same IOVA page may be handed out again for a different PA.
 *
 * LIFETIME CONTRACT
 * -----------------
 *  Map runs on the output thread: bounded polling only, no sleep, no reentry.
 *  Retire runs only from the dedicated workloop timer and may poll commands.
 *  Completion (interrupt/polling context) only stamps the hardware completion
 *  and moves the state; it never invalidates, frees or waits.
 *
 *  States, in order: kIdle -> kMapping -> kPosting -> kSubmitted ->
 *  kPending -> kRetiring -> kIdle. kPosting is published BEFORE the first OWN
 *  and means "descriptors are being recorded, retirement must not start".
 *  The commit (r17TxPosted) publishes kSubmitted; if a completion was already
 *  observed (doneSeen), the commit publishes kPending itself. This is the
 *  submission/completion handoff: a very fast completion cannot make the
 *  retire path read a half-filled witness of the generation being submitted.
 *
 *  - Map success: nonzero handle, per-segment IOVA, all invalidations done.
 *  - Map failure with handle == 0: no translation and no command remains live
 *    (the driver may free the mbuf). Budget/evidence exhaustion is this case.
 *  - Map failure with handle != 0: the driver keeps the mbuf, queues Retire.
 *  - Retire failure: the backend keeps the handle; the driver keeps the mbuf
 *    and retries. Only a successful Retire (invalidation confirmed) allows the
 *    mbuf to be freed and the IOVA/PT slots to be reused.
 *  - Detach only from Idle with no live owner. Detach failure pins resources.
 */
namespace r17tx {
static const char kFunctionName[] = "RTL812xTxMapNative-v1";
/* Round21 raises the ABI to 3: Configure gained the four window-edge fields.
 * Round22 raises it to 4: the window edges gained the SUBMISSION BARRIER
 * (inFlight/ringOwn/edgeSeq) and the boundary timestamps the exit sequence is
 * checked against. Both sides validate `bytes == sizeof(Configure)` and
 * `version == kVersion`, so an old probe with a new driver (or the reverse) is
 * refused at Install instead of silently sharing a layout that no longer means
 * the same thing.
 *
 * Round23 does NOT bump it: no field changed meaning or position, only how many
 * requests the driver keeps live at once (`kSlots`). `held`/`maxHeld` already
 * report that as a number, so an old probe can read a new driver and simply see
 * a peak above 1 -- which is exactly the fact this round adds.
 *
 * ROUND 23 ADDS kSlots: the driver keeps this many mappings alive at once, each
 * in its own fixed stripe of the IOVA window (`amdtx::kPagesPerSlot` pages).
 * It lives here rather than in the driver because the probe's map side has to
 * size the same window, and a mismatch would show up as two generations
 * aliasing one IOVA range. */
/* Round25: fixed history is circular and no longer an admission limit.
 * Round26: mode 2 maps ordinary TX; Request::reqId is then a driver-assigned
 * monotonic map-attempt sequence, and token identifies the installed run. The
 * layout stays fixed, but old code must not silently interpret these as packet
 * selection fields. */
/* Round29: standard complete() requires per-handle backend retirement ack.
 * Quiesce reports both held mbufs and live generations; layout is unchanged. */
static const uint32_t kVersion = 7, kMaxSegments = 8, kMaxPages = 16;
static const uint32_t kSlots = 4;
/* Evidence and legacy packet-selection bounds. The live DMA-owner bound is
 * kSlots; all-standard mode does not use kRequestLimit for admission. */
static const uint32_t kMaxRequests = 32; // fixed retained history
static const uint32_t kRequestLimit = 512; // selected direct/standard modes only
/* Protocol upper bound, not a promise that one four-page slot fits this much.
 * The mapper still rejects a layout beyond its per-slot page capacity. */
static const uint64_t kMaxBytes = 65536;
enum { kInstall = 1, kDisarm = 2, kQuery = 3, kDetach = 4 };
/* kMap/kRetire are the owned mapping. kCover (round 20) asks the backend to
 * make the packet's OWN physical ranges readable through the device page table
 * before any OWN, and is valid while another generation owns the mapping slot:
 * the point is precisely that ordinary traffic keeps flowing.
 *
 * Round 21 adds the two window edges. They exist because "translation is on" is
 * a property of the whole period, while the ordinary output path keeps
 * submitting: the driver must be able to stop new ordinary submissions and know
 * when the ones already handed to hardware are done, BEFORE the probe flips the
 * translation and after it flips it back.
 *
 * ROUND 22 CHANGES WHAT THESE MEAN. Round 21's kQuiesce only published a gate
 * flag and a ring occupancy, and the probe treated "gate is closed" as "nothing
 * more can be submitted". That is false: an output thread can pass the gate
 * read, be descheduled, and write its OWN bit afterwards. Draining then reports
 * "empty" while a descriptor is still on its way, and the DTE flip races it.
 * The gate is therefore an ADMISSION WORD, not a flag:
 *
 *   bit 31      closed
 *   bits 0..30  admitted submissions that have not yet reached their OWN write
 *
 *   kQuiesce -- atomically sets `closed` AND reports `inFlight` (the count
 *               above) plus `ringOwn` (total ring occupancy, selected slots
 *               included). It never sleeps and never waits: the probe's own
 *               thread polls it, because the caller must NOT block the driver's
 *               workloop -- that is the context that reaps completed
 *               descriptors, so waiting there would wait for itself.
 *   kResume  -- refuses (Busy) while inFlight != 0; otherwise opens the word.
 *               Only the probe calls it, and only after the hardware restore
 *               was confirmed.
 *
 * A submission is admitted by an atomic CAS on that one word, so "gate is open"
 * and "my reference is counted" are the same indivisible step. It is released
 * after the OWN bit is set, so the pair
 *
 *      inFlight == 0  &&  ringOwn == 0
 *
 * cannot be true while any descriptor is between admission and completion:
 * txNextDescIndex is advanced inside the admitted region, and the ring only
 * shrinks as the device completes descriptors.
 *
 * `edgeSeq`/`tEdge` name the ACTUAL transition (close or open) and when it
 * happened, so a probe-side timestamp is never confused with the event.
 * `tSubmitDone`/`tDrainDone` are the first observations of inFlight==0 and of
 * (inFlight==0 && ringOwn==0) after a close; they are never overwritten by a
 * later poll, which is what round 20 got wrong in the other direction. */
/* Request callback ops are a separate channel and may reuse Configure values.
 * Window-edge ops travel in Configure::op and must not collide with its
 * kInstall/kDisarm/kQuery/kDetach values (1..4).
 * kQuiesce was 4 in the first draft of round 21 -- the same value as kDetach --
 * and every Detach was silently executed as a Quiesce. The window-edge ops
 * therefore start above the control range. */
enum { kMap = 1, kRetire = 2, kCover = 3, kRetireAck = 4,
       kQuiesce = 16, kResume = 17,
       /* kSample asks the driver to publish a ring record for ONE named window
        * step (Configure.state carries the r20tx::kStage* value). It exists
        * because re-using kQuiesce to force a sample makes the record say
        * "quiesce" when the caller meant "exit" -- which is the same class of
        * mistake round 20 shipped. */
       kSample = 18 };
enum { kIdle = 0, kMapping = 1, kPosting = 2, kSubmitted = 3, kPending = 4,
       kRetiring = 5, kControl = 6 };
#if defined(__cplusplus)
/* ---- ABI guards -----------------------------------------------------------
 * Round 21 shipped `kQuiesce = 4` while `kDetach` was also 4. Both travel in the
 * same Configure::op word, so EVERY Detach was silently executed as a Quiesce:
 * the callback was never cleared, the gate was never reset, and the probe
 * reported a clean window it had not actually closed. Nothing caught it --
 * not the compiler, not the host tests, not three hardware runs -- because the
 * collision was only ever a semantic one.
 *
 * These assertions make the classes of mistake that produced it unbuildable:
 *   * a control op colliding with another control op;
 *   * a window-edge op colliding with a control op (same op word);
 *   * duplicate request op or state values within their own channels.
 * If a future round adds an op, the build fails here instead of on the machine.
 */
static_assert(kInstall != kDisarm && kInstall != kQuery && kInstall != kDetach &&
              kDisarm != kQuery && kDisarm != kDetach && kQuery != kDetach,
              "Configure ops must be distinct");
static_assert(kQuiesce != kInstall && kQuiesce != kDisarm &&
              kQuiesce != kQuery && kQuiesce != kDetach &&
              kQuiesce != kResume && kQuiesce != kSample,
              "window-edge ops must not collide with control ops");
static_assert(kResume != kInstall && kResume != kDisarm && kResume != kQuery &&
              kResume != kDetach && kResume != kSample,
              "window-edge ops must not collide with control ops");
static_assert(kSample != kInstall && kSample != kDisarm && kSample != kQuery &&
              kSample != kDetach,
              "window-edge ops must not collide with control ops");
static_assert(kMap != kRetire && kMap != kCover && kMap != kRetireAck &&
              kRetire != kCover && kRetire != kRetireAck && kCover != kRetireAck,
              "Request ops must be distinct");
/* NOTE: Request ops (kMap=1, kRetire=2, kCover=3, kRetireAck=4) DO share values with the
 * control ops (kInstall=1, kDisarm=2, kQuery=3, kDetach=4). That is deliberate:
 * the callback's op argument and Configure::op are separate channels,
 * and no code path compares one against the other. Asserting they differ would
 * be asserting a property the design does not have -- an over-eager guard that
 * rejects correct code is worse than no guard, because the next person
 * "fixes" it by renumbering and breaks the archived round-17/18 ABI.
 *
 * What MUST hold is that within each field the values are distinct, and that
 * the window-edge ops do not collide with anything (they are the ones that were
 * mis-numbered into the control range in the first draft). Both are asserted
 * above.
 */
/* States are stored in Configure::state and in the driver's state machine. */
static_assert(kIdle != kControl && kIdle != kMapping && kControl != kMapping,
              "state values must be distinct");

#endif
struct Segment { uint64_t address, length; };
struct Request {
    uint32_t version, bytes, bdf, token, reqId, count;
    /* In all-standard mode token is the run token and reqId is the internal
     * map-attempt sequence; neither is required to appear in packet bytes. */
    uint64_t handle; // Map input=0. Any nonzero output owns a cleanup obligation.
    /* kRetireAck: query immediately after standard complete(), using the
     * unique stdHandle, bdf and installed run token. Success returns tRetire
     * only after that handle's PTE clear and retire CompletionWait completed.
     * reqId/iova are not lookup keys: a prepare rollback may lack segments. */
    uint64_t tMap, tDone, tRetire; // mach ticks; backend stamps map/retire
    /* Actual physical segments of the real packet. The driver fills these from
     * getPhysicalSegmentsWithCoalesce() before any OWN and never rewrites them. */
    Segment physical[kMaxSegments];
    /* Map output: same count/order/length/offset, different start address. */
    Segment iova[kMaxSegments];
};
typedef IOReturn (*Callback)(void *context, uint32_t op, Request *request);
struct Configure {
    uint32_t version, bytes, op, bdf, token, state;
    // Mach ticks: nonzero > now prevents new Map at expiry;
    // 0 keeps an all-standard session active until explicit Disarm.
    uint64_t deadline;
    Callback callback;
    void *context;
    IOService *owner; // retained by the driver until successful Detach
    uint64_t handle;  // Reserved output (0); failure with nonzero => pinned
    uint32_t mapped, completed, retired, dropped;
    /* Round17 accounting, read-only for the probe. `held` is the number of
     * mbufs the driver still owns on behalf of live mappings: 0..kSlots. */
    uint32_t held, maxHeld, evidenceUsed, rejected;
    /* Round18 (additive, no version bump: `bytes` is validated against
     * sizeof(*this) on both sides, so a mixed pair is refused at Install).
     *   mode   -- kModeDirect keeps the round-17 platform-call mapping; the
     *             driver then never creates an IODMACommand for a packet.
     *             kModeStandard makes the driver hand each selected packet's
     *             IOMemoryDescriptor to an IODMACommand built with `mapper`,
     *             i.e. IOKit performs the map/unmap; kRetireAck independently
     *             confirms the backend retirement before the driver frees.
     *             kModeAllStandard uses the same standard objects for EVERY
     *             packet in the finite window, without token/req selection.
     *             Install refuses this mode while TSO4 or TSO6 is enabled;
     *             offload capabilities must be configured before driver start.
     *   mapper -- the probe's own IOMapper (never the system mapper, which is
     *             verified NULL in this kext). Ignored in kModeDirect. */
    void *mapper;
    uint32_t mode, modeReserved; // Round29 control output: live generations (including retiring)
    /* Round21 window edges (additive; `bytes` is validated against sizeof on
     * both sides, so a mixed probe/driver pair is refused at Install).
     *   quiesced    -- 1: the admission word is closed, no new submission is
     *                  admitted. Set by kQuiesce, cleared by kResume.
     *   outstanding -- ring occupancy EXCLUDING the selected generation's slots.
     *                  Kept because it is the number the round-21 report quotes;
     *                  it is NOT what the drain must reach zero on (see ringOwn).
     *   activeCover -- cover calls currently inside the backend. Must be 0
     *                  before the probe clears callback/context/backend.
     *   gateFails   -- control ops refused because the state did not allow them.
     *
     * Round22 window barrier. These are the facts the enter/exit order is
     * checked against, each named for the event it records:
     *   inFlight    -- admitted submissions that have not set their OWN bit yet.
     *                  Zero is a precondition for both the DTE flip and kResume.
     *   ringOwn     -- total descriptor occupancy, selected slots INCLUDED. The
     *                  drain target: hardware must own nothing before the table
     *                  it translates through is replaced.
     *   edgeSeq     -- number of actual admission-word transitions so far.
     *   barrierFails-- submissions refused because the word was closed.
     *   tEdge       -- when the most recent transition happened (mach ticks).
     *   tSubmitDone -- first time inFlight==0 after the most recent close.
     *   tDrainDone  -- first time inFlight==0 && ringOwn==0 after that close.
     *   tResume     -- when kResume last opened the word.
     * The three "first time" stamps are latched, not re-sampled: a later poll
     * must not move the boundary it is supposed to report. */
    uint32_t quiesced, outstanding, activeCover, gateFails;
    uint32_t inFlight, ringOwn, edgeSeq, barrierFails;
    uint64_t tEdge, tSubmitDone, tDrainDone, tResume;
};
enum { kModeDirect = 0, kModeStandard = 1, kModeAllStandard = 2 };
#if defined(__cplusplus)
/* Round 21 added four fields to Configure; both sides validate bytes against
 * sizeof, so a stale header on either side is refused at Install rather than
 * silently sharing a layout that no longer means the same thing. Pinning the
 * size makes an accidental field addition a deliberate act: change this number
 * AND bump kVersion, or the build fails. */
/* sizeof alone is NOT enough: this struct is 8-byte aligned because it holds
 * uint64_t members, so deleting one of the trailing uint32_t fields leaves the
 * total at 128 and a size-only assert stays silent. Verified by deleting
 * `gateFails` and watching the assert pass. The per-field offsets are what
 * actually pin the layout; if a field is removed, __builtin_offsetof fails to
 * compile because the member no longer exists. */
static_assert(sizeof(Configure) == 176,
              "Configure layout changed: bump kVersion on both sides");
/* These numbers were MEASURED, not derived: an earlier draft of this guard
 * asserted mapper==104 and the compiler rejected it (actual 96), which is the
 * same "typed it from memory" failure that produced the 2328-vs-2320 block bug.
 * tools/r21/abi.py prints them from the real headers if they ever need updating. */
static_assert(__builtin_offsetof(Configure, deadline) == 24, "Configure::deadline moved");
static_assert(__builtin_offsetof(Configure, callback) == 32, "Configure::callback moved");
static_assert(__builtin_offsetof(Configure, context) == 40, "Configure::context moved");
static_assert(__builtin_offsetof(Configure, owner) == 48, "Configure::owner moved");
static_assert(__builtin_offsetof(Configure, handle) == 56, "Configure::handle moved");
static_assert(__builtin_offsetof(Configure, mapper) == 96, "Configure::mapper moved");
static_assert(__builtin_offsetof(Configure, mode) == 104, "Configure::mode moved");
static_assert(__builtin_offsetof(Configure, quiesced) == 112, "Configure::quiesced moved");
static_assert(__builtin_offsetof(Configure, outstanding) == 116, "Configure::outstanding moved");
static_assert(__builtin_offsetof(Configure, activeCover) == 120, "Configure::activeCover moved");
static_assert(__builtin_offsetof(Configure, gateFails) == 124, "Configure::gateFails moved");
static_assert(__builtin_offsetof(Configure, inFlight) == 128, "Configure::inFlight moved");
static_assert(__builtin_offsetof(Configure, ringOwn) == 132, "Configure::ringOwn moved");
static_assert(__builtin_offsetof(Configure, edgeSeq) == 136, "Configure::edgeSeq moved");
static_assert(__builtin_offsetof(Configure, barrierFails) == 140, "Configure::barrierFails moved");
static_assert(__builtin_offsetof(Configure, tEdge) == 144, "Configure::tEdge moved");
static_assert(__builtin_offsetof(Configure, tSubmitDone) == 152, "Configure::tSubmitDone moved");
static_assert(__builtin_offsetof(Configure, tDrainDone) == 160, "Configure::tDrainDone moved");
static_assert(__builtin_offsetof(Configure, tResume) == 168, "Configure::tResume moved");
static_assert(sizeof(Request) == 312,
              "Request layout changed: bump kVersion on both sides");
#endif
struct Descriptor { uint64_t address, length; uint32_t opts1, opts2; };
struct Witness {
    Request request;
    uint64_t tOwn, tFree; // tFree is stamped AFTER the mbuf was released
    uint32_t cumulative, firstSlot, lastSlot, retired;
    uint32_t doneClose, closeMask; // actual close register sample + modulo mask
    Descriptor descriptors[kMaxSegments]; // as programmed at posting time
    /* Read back from the ring at retirement: the hardware's own final words.
     * A descriptor the device dropped carries an error bit here, which is the
     * difference between "the frame was never offered" and "the frame was
     * offered and the device refused it". */
    uint32_t doneOpts1[kMaxSegments];
};
struct Snapshot {
    uint32_t magic, version, bytes, count; // magic=0x37315854 (native TX17)
    uint32_t bdf, token, dropped, state;
    uint32_t retired, rejected, maxHeld, historyStart; // absolute oldest retired sequence; index=seq%32
    /* TX ring accounting at publication time. These are diagnostics, not
     * verdicts: they say whether the driver's completion walk could even have
     * reached this generation's slot. */
    uint32_t txNext, txDirty, txClose, txFree;
    uint32_t txDescDone, completeCalls, completeHits, lastSeenSlot;
    uint64_t tPublished;
    Witness witnesses[kMaxRequests];
};
static const uint32_t kSnapshotHeaderBytes = 88;
static const uint32_t kWitnessBytes = 576;
/* Install only Idle/uninstalled/non-VTD, matching BDF and a nonzero token.
 * One installation per driver start; Detach keeps the token filter (DROP
 * forever), the state allocation and a harmless timer until stop.
 * Every selected-token request uses mapping or DROP, never identity fallback. */
}
#endif
