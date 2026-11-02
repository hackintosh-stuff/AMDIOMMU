#!/usr/bin/env python3
"""apply-lucy-obs.py -- add the round-9 observation log to a pristine RTL812xLucy
source tree.

WHY A PATCH SCRIPT RATHER THAN EDITED FILES IN THE WORKSPACE
-----------------------------------------------------------
The driver source is third-party (Laura Mueller, GPL-2.0, commit
639144d1f284a9fee222a518691b01494f5e265d). Keeping a hand-edited copy in the
workspace would make it impossible to tell, later, which bytes are upstream and
which are ours. This script applies named, individually described insertions to
a pristine tree and refuses to run twice, so the delta is always reproducible
from the upstream tarball.

WHAT IT ADDS, AND WHERE
-----------------------
  1. RTL812xObsLog.hpp            new file, the wire format
  2. RTL812xLucy.hpp              includes it; adds obsRegion/obsHdr/obsRecs
                                  members and three helper declarations
  3. RTL812xLucy.cpp  start()     allocates the log after setupStatResources()
  4. RTL812xLucy.cpp  stop()      frees it before the ring teardown
  5. RTL812xLucy.cpp  outputStart()  records every descriptor it fills, and
                                     records the doorbell
  6. RTL812xLucy.cpp  txInterrupt()  records every descriptor handed back
  7. RTL812xLucy.cpp  rxInterrupt()  records every descriptor it reaps
  8. RTL812xLucy.cpp  new methods: obsInit/obsFree/obsWrite/obsPublish

Every insertion is a plain memory write or an IORegistry property set. None of
them changes how DMA is mapped, and none of them touches a device register.

Usage:
    py -3 tools/apply-lucy-obs.py <path-to-RTL812xLucy-commit-dir>
Exit 0 = applied (or already applied). Non-zero = refused, with the reason.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
HDR_SRC = os.path.join(HERE, "lucy-obs", "RTL812xObsLog.hpp")

MARK_HPP = "#include \"RTL812xObsLog.hpp\""
MARK_CPP = "RTL8125::obsWrite"

# ---------------------------------------------------------------------------
# 2. RTL812xLucy.hpp
# ---------------------------------------------------------------------------
HPP_INCLUDE_OLD = '#include "RTL8125LucyRxPool.hpp"\n'
HPP_INCLUDE_NEW = ('#include "RTL8125LucyRxPool.hpp"\n'
                   '/* Round 9: bounded submit/complete metadata log. */\n'
                   '#include "RTL812xObsLog.hpp"\n')

HPP_MEMBERS_OLD = """    bool wolCapable;
    bool enableTSO4;
    bool enableTSO6;
    bool useAppleVTD;
    bool hasSensor;
"""
HPP_MEMBERS_NEW = """    bool wolCapable;
    bool enableTSO4;
    bool enableTSO6;
    bool useAppleVTD;
    bool hasSensor;

    /* Round 9: the submit/complete observation log.
     *
     * This is the driver's own live memory object. The probe never maps it by
     * physical address: obsPublish() copies a suffix of it into an IORegistry
     * property, so a reader receives bytes the driver copied out of an object
     * it still holds. That is what makes the read basis an object identity
     * rather than "a register contained this address".
     */
    IOBufferMemoryDescriptor *obsRegion;
    RtlObsHdr *obsHdr;
    RtlObsRec *obsRecs;
    /* Publication staging buffer. A member, not a local: 512 records is about
     * 28 KiB, far past the kernel stack. */
    RtlObsRec obsShadow[kObsPublishMax];
    UInt32 obsTxBatch;      /* first cumulative index of the packet being sent */
    UInt32 obsRxReaped;     /* cumulative count of reaped RX descriptors */
    UInt32 obsDropped;      /* records lost because a slot was overwritten */

    bool     obsInit();
    void     obsFree();
    void     obsWrite(UInt32 kind, UInt32 cumulative, UInt32 slot, UInt32 gen,
                      UInt64 addr, UInt32 opts1, UInt32 opts2, UInt32 len,
                      UInt32 flags);
    void     obsPublish();
"""

HPP_DECL_OLD = ""
HPP_DECL_NEW = ""

START_OLD = """    if (!setupStatResources()) {
        IOLog("Error allocating Stat resources.\\n");
        goto error_dma3;
    }
"""
START_NEW = """    if (!setupStatResources()) {
        IOLog("Error allocating Stat resources.\\n");
        goto error_dma3;
    }

    /* Round 9: allocate the observation log. A failure here is NOT fatal --
     * the NIC works fine without it, and refusing to start the interface
     * because a diagnostic buffer could not be allocated would be worse than
     * starting it with no diagnostics. obsInit() records the failure and
     * obsPublish() reports "unavailable" so the absence is visible. */
    if (!obsInit()) {
        IOLog("Observation log unavailable; continuing without it.\\n");
    }
"""

STOP_OLD = """    freeStatResources();
    freeRxResources();
    freeTxResources();
"""
STOP_NEW = """    /* Round 9: publish a last snapshot, then release the log before the
     * rings it describes are torn down. */
    obsPublish();
    obsFree();

    freeStatResources();
    freeRxResources();
    freeTxResources();
"""

TIMER_OLD = """    rtl812xDumpTallyCounter(tp);
"""
TIMER_NEW = """    rtl812xDumpTallyCounter(tp);

    /* Round 9: refresh the published observation log once per watchdog tick
     * (kTimerPeriod = 1 s). The probe's measurement window opens about 20 s
     * after boot and runs for 3 s, so a reader that arrives mid-window sees a
     * publication no more than a second old. obsPublish() is a bounded memcpy
     * plus one property set; it does not touch the device. */
    obsPublish();
"""

# ---------------------------------------------------------------------------
# 5. outputStart()
# ---------------------------------------------------------------------------
OUTPUT_OLD = """        OSAddAtomic(-numSegs, &txNumFreeDesc);
        index = txNextDescIndex;
        txNextDescIndex = (txNextDescIndex + numSegs) & kTxDescMask;
        txTailPtr0 += numSegs;
        firstDesc = &txDescArray[index];
        lastSeg = numSegs - 1;
"""
OUTPUT_NEW = """        OSAddAtomic(-numSegs, &txNumFreeDesc);
        index = txNextDescIndex;
        txNextDescIndex = (txNextDescIndex + numSegs) & kTxDescMask;
        /* Round 9: remember where this packet starts in the cumulative index
         * space. txTailPtr0 is the driver's own submit counter, so
         * (txTailPtr0 + i) is the exact cumulative index of the i-th
         * descriptor of this packet -- the same number the hardware will
         * later report through the close pointer. */
        obsTxBatch = txTailPtr0;
        txTailPtr0 += numSegs;
        firstDesc = &txDescArray[index];
        lastSeg = numSegs - 1;
"""

OUTPUT_FILL_OLD = """            desc->addr = OSSwapHostToLittleInt64(txSegments[i].location);
            desc->opts2 = OSSwapHostToLittleInt32(opts2);
            desc->opts1 = OSSwapHostToLittleInt32(opts1);
"""
OUTPUT_FILL_NEW = """            desc->addr = OSSwapHostToLittleInt64(txSegments[i].location);
            desc->opts2 = OSSwapHostToLittleInt32(opts2);
            desc->opts1 = OSSwapHostToLittleInt32(opts1);

            /* Round 9: record the descriptor exactly as it was programmed.
             * `len` is the real segment length (txSegments[i].length), which
             * is the one thing a reader of the ring cannot recover when the
             * descriptor carries a TSO command bit. `flags` says whether that
             * happened, so the length is never silently a guess. */
            {
                UInt32 oflags = 0;
                if (cmd & (GiantSendv4 | GiantSendv6 | LargeSend))
                    oflags |= kObsFlagLenUnknown | kObsFlagTso;
                if (i == 0)
                    oflags |= kObsFlagFirstFrag;
                if (i == lastSeg)
                    oflags |= kObsFlagLastFrag;
                if (index == kTxLastDesc)
                    oflags |= kObsFlagRingEnd;
                if (opts1 & DescOwn)
                    oflags |= kObsFlagDescOwn;
                obsWrite(kObsKindTxSubmit,
                         obsTxBatch + i,
                         index,
                         (obsTxBatch + i) / kNumTxDesc,
                         txSegments[i].location,
                         opts1, opts2,
                         (UInt32)txSegments[i].length,
                         oflags);
            }
"""

OUTPUT_DOORBELL_OLD = """    /* Update tail pointer. */
    rtl812xDoorbell(&linuxData, txTailPtr0);
"""
OUTPUT_DOORBELL_NEW = """    /* Update tail pointer. */
    rtl812xDoorbell(&linuxData, txTailPtr0);

    /* Round 9: the doorbell is the moment the device is told the descriptors
     * exist. Recording it lets a reader separate "filled in" from "offered to
     * the device", which are two different claims. */
    obsWrite(kObsKindTxDoorbell, txTailPtr0, 0, 0, 0, 0, 0, 0, 0);
"""

# ---------------------------------------------------------------------------
# 6. txInterrupt()
# ---------------------------------------------------------------------------
TXDONE_OLD = """    numDone = ((nextClosePtr - txClosePtr0) & tp->MaxTxDescPtrMask);

#ifdef DEBUG_INTR
    DebugLog("txInterrupt() numDone: %u.\\n", numDone);
#endif  /* DEBUG_INTR */

    txClosePtr0 = nextClosePtr;

    while (numDone-- > 0) {
        m = txMbufArray[txDirtyDescIndex];
        txMbufArray[txDirtyDescIndex] = NULL;
"""
TXDONE_NEW = """    numDone = ((nextClosePtr - txClosePtr0) & tp->MaxTxDescPtrMask);

#ifdef DEBUG_INTR
    DebugLog("txInterrupt() numDone: %u.\\n", numDone);
#endif  /* DEBUG_INTR */

    /* Round 9: record each descriptor the device handed back, with the same
     * cumulative index the submit record used. A reader can therefore join
     * submit and completion on (cumulative) alone, without assuming anything
     * about slot reuse. `txClosePtr0` is the driver's own completion counter,
     * read from the hardware close pointer, so this is the same number that
     * produced numDone. */
    {
        UInt32 doneCum = txClosePtr0;
        UInt32 doneLeft = numDone;
        UInt32 doneIdx = txDirtyDescIndex;
        while (doneLeft-- > 0) {
            obsWrite(kObsKindTxDone,
                     doneCum,
                     doneIdx,
                     doneCum / kNumTxDesc,
                     0, 0, 0, 0, 0);
            doneCum++;
            ++doneIdx &= kTxDescMask;
        }
    }

    txClosePtr0 = nextClosePtr;

    while (numDone-- > 0) {
        m = txMbufArray[txDirtyDescIndex];
        txMbufArray[txDirtyDescIndex] = NULL;
"""

# ---------------------------------------------------------------------------
# 7. rxInterrupt()
# ---------------------------------------------------------------------------
RX_OLD = """        /* Finally update the descriptor and get the next one to examine. */
    nextDesc:
        desc->buf.addr = OSSwapHostToLittleInt64(addr);
        desc->buf.blen = OSSwapHostToLittleInt64(word1);
"""
RX_NEW = """        /* Finally update the descriptor and get the next one to examine. */
    nextDesc:
        /* Round 9: record the descriptor the device filled for us. `addr` is
         * the buffer the driver is handing back to the device (the one just
         * re-programmed), and `pktSize` is what the device reported. The
         * received payload's own buffer address was
         * rxBufArray[rxNextDescIndex].phyAddr BEFORE this update, which is
         * what `obsRxAddr` captured below. */
        obsWrite(kObsKindRxDone,
                 obsRxReaped,
                 rxNextDescIndex,
                 obsRxReaped / kNumRxDesc,
                 obsRxAddr,
                 (UInt32)(descStatus1 & 0xFFFFFFFFu),
                 descStatus2,
                 (UInt32)pktSize,
                 (descStatus1 & RxRES) ? kObsFlagRxError : 0);
        obsRxReaped++;

        desc->buf.addr = OSSwapHostToLittleInt64(addr);
        desc->buf.blen = OSSwapHostToLittleInt64(word1);
"""

RX_CAPTURE_OLD = """    while (!((descStatus1 = OSSwapLittleToHostInt32(desc->cmd.opts1)) & DescOwn) && (goodPkts < maxCount)) {
        word1 = (rxNextDescIndex == kRxLastDesc) ? (kRxBufferSize | DescOwn | RingEnd) : (kRxBufferSize | DescOwn);
        addr = rxBufArray[rxNextDescIndex].phyAddr;
"""
RX_CAPTURE_NEW = """    while (!((descStatus1 = OSSwapLittleToHostInt32(desc->cmd.opts1)) & DescOwn) && (goodPkts < maxCount)) {
        word1 = (rxNextDescIndex == kRxLastDesc) ? (kRxBufferSize | DescOwn | RingEnd) : (kRxBufferSize | DescOwn);
        addr = rxBufArray[rxNextDescIndex].phyAddr;
        /* Round 9: the address the DEVICE wrote into, captured before the
         * descriptor is re-programmed below. */
        obsRxAddr = addr;
"""

RX_DECL_OLD = """    UInt32 descStatus1, descStatus2;
    SInt32 pktSize;
    UInt32 goodPkts = 0;
    bool replaced;
"""
RX_DECL_NEW = """    /* Round 9: descStatus2 and pktSize are read on the RxRES path, which
     * jumps to nextDesc before assigning them. They were uninitialised there
     * before this round; the observation record would have made that visible
     * as garbage rather than harmless, so they are now initialised. */
    UInt32 descStatus1, descStatus2 = 0;
    SInt32 pktSize = 0;
    UInt32 goodPkts = 0;
    bool replaced;
    UInt64 obsRxAddr = 0;
"""

# ---------------------------------------------------------------------------
# 8. the new methods, appended before the last line of the file
# ---------------------------------------------------------------------------
OBS_METHODS = """
#pragma mark --- round 9 observation log ---

/* Allocate the log. Returns false when the buffer could not be created, in
 * which case every obsWrite() is a no-op and obsPublish() says so. */
bool RTL8125::obsInit()
{
    obsRegion = NULL;
    obsHdr = NULL;
    obsRecs = NULL;
    obsTxBatch = 0;
    obsRxReaped = 0;
    obsDropped = 0;

    obsRegion = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(
        kernel_task,
        (kIODirectionOut | kIOMemoryPhysicallyContiguous |
         kIOMemoryHostPhysicallyContiguous),
        kObsRegionBytes,
        0xFFFFFFFFFFFFFF00ULL);

    if (!obsRegion) {
        IOLog("obsInit(): could not allocate the observation log.\\n");
        return false;
    }
    if (obsRegion->prepare() != kIOReturnSuccess) {
        IOLog("obsInit(): prepare() failed.\\n");
        obsRegion->release();
        obsRegion = NULL;
        return false;
    }
    obsHdr = (RtlObsHdr *)obsRegion->getBytesNoCopy();
    if (!obsHdr) {
        obsRegion->complete();
        obsRegion->release();
        obsRegion = NULL;
        return false;
    }
    bzero(obsHdr, (size_t)kObsRegionBytes);
    obsHdr->magic = kObsMagic;
    obsHdr->version = kObsVersion;
    obsHdr->recSize = (UInt32)sizeof(RtlObsRec);
    obsHdr->capacity = kObsCapacity;
    obsHdr->tStart = mach_absolute_time();
    obsRecs = (RtlObsRec *)((UInt8 *)obsHdr + sizeof(RtlObsHdr));

    /* Publish the identity and the geometry immediately, so a reader can tell
     * "the log exists but is empty" from "the log was never created". */
    setProperty("rtl812x-obs-format", kObsFormat);
    setProperty("rtl812x-obs-state", "allocated");
    obsPublish();
    return true;
}

void RTL8125::obsFree()
{
    if (obsRegion) {
        obsRegion->complete();
        obsRegion->release();
        obsRegion = NULL;
    }
    obsHdr = NULL;
    obsRecs = NULL;
}

/* Append one record.
 *
 * The index is claimed atomically so two threads cannot write the same slot.
 * `seq` is written last, after a barrier, so a reader that sees the new seq
 * knows the body is complete. A slot that is claimed twice before a reader
 * arrives loses its older content; that is counted in `wrapped` rather than
 * hidden, and the reader also sees the seq discontinuity.
 */
void RTL8125::obsWrite(UInt32 kind, UInt32 cumulative, UInt32 slot, UInt32 gen,
                       UInt64 addr, UInt32 opts1, UInt32 opts2, UInt32 len,
                       UInt32 flags)
{
    if (!obsHdr || !obsRecs) return;

    const UInt32 absolute =
        __atomic_fetch_add(&obsHdr->head, 1u, __ATOMIC_RELAXED);
    const UInt32 seq = absolute + 1u;
    RtlObsRec *r = &obsRecs[absolute & kObsCapacityMask];

    if (r->seq != 0 && r->seq != absolute) {
        /* The slot still holds an older, unread record. */
        __atomic_fetch_add(&obsHdr->wrapped, 1u, __ATOMIC_RELAXED);
        obsDropped++;
    }

    r->tMono = mach_absolute_time();
    r->addr = addr;
    r->kind = kind;
    r->cumulative = cumulative;
    r->slot = slot;
    r->gen = gen;
    r->batch = obsTxBatch;
    r->opts1 = opts1;
    r->opts2 = opts2;
    r->len = len;
    r->flags = flags;
    __atomic_thread_fence(__ATOMIC_RELEASE);
    r->seq = seq;
}

/* Copy a suffix of the log into an IORegistry property.
 *
 * The copy is what makes the read basis an OBJECT identity: the probe receives
 * bytes the driver copied out of a descriptor it still holds, and never
 * dereferences a physical address. Header fields are published separately so a
 * reader can tell a complete publication from a truncated one.
 *
 * `obsShadow` is a fixed member buffer, not a stack array: a 512-record copy is
 * 34 KiB, which would blow the kernel stack.
 */
void RTL8125::obsPublish()
{
    char numbuf[32];

    if (!obsHdr || !obsRecs) {
        setProperty("rtl812x-obs-state", "unavailable");
        setProperty("rtl812x-obs-head", "0x0");
        setProperty("rtl812x-obs-published", "0x0");
        setProperty("rtl812x-obs-wrapped", "0x0");
        return;
    }

    const UInt32 head = __atomic_load_n(&obsHdr->head, __ATOMIC_RELAXED);
    UInt32 n = (head < kObsPublishMax) ? head : kObsPublishMax;
    const UInt32 first = head - n;      /* absolute index of the first copied */

    /* A suffix of the log is contiguous in absolute index, so it occupies at
     * most two runs of the ring. Copy run by run. */
    UInt32 copied = 0;
    while (copied < n) {
        const UInt32 abs = first + copied;
        const UInt32 off = abs & kObsCapacityMask;
        UInt32 run = kObsCapacity - off;
        if (run > n - copied) run = n - copied;
        memcpy(&obsShadow[copied], &obsRecs[off],
               (size_t)run * sizeof(RtlObsRec));
        copied += run;
    }

    OSData *blob = OSData::withBytes(obsShadow,
                                     (UInt32)(n * sizeof(RtlObsRec)));
    if (blob) {
        setProperty("rtl812x-obs-records", blob);
        blob->release();
    }

    setProperty("rtl812x-obs-format", kObsFormat);
    setProperty("rtl812x-obs-state", obsDropped ? "wrapped" : "ok");

    snprintf(numbuf, sizeof(numbuf), "0x%x", (unsigned)head);
    setProperty("rtl812x-obs-head", numbuf);
    snprintf(numbuf, sizeof(numbuf), "0x%x", (unsigned)n);
    setProperty("rtl812x-obs-published", numbuf);
    snprintf(numbuf, sizeof(numbuf), "0x%x", (unsigned)first);
    setProperty("rtl812x-obs-first", numbuf);
    snprintf(numbuf, sizeof(numbuf), "0x%x", (unsigned)obsDropped);
    setProperty("rtl812x-obs-wrapped", numbuf);
    snprintf(numbuf, sizeof(numbuf), "0x%x", (unsigned)sizeof(RtlObsRec));
    setProperty("rtl812x-obs-rec-size", numbuf);
    snprintf(numbuf, sizeof(numbuf), "0x%llx",
             (unsigned long long)obsHdr->tStart);
    setProperty("rtl812x-obs-t-start", numbuf);
    snprintf(numbuf, sizeof(numbuf), "0x%llx",
             (unsigned long long)mach_absolute_time());
    setProperty("rtl812x-obs-t-published", numbuf);
}
"""


def read(path):
    with open(path, "r", encoding="utf-8", errors="surrogateescape") as f:
        return f.read()


def write(path, text):
    with open(path, "w", encoding="utf-8", errors="surrogateescape",
              newline="\n") as f:
        f.write(text)


def replace_once(text, old, new, what):
    n = text.count(old)
    if n != 1:
        raise SystemExit(
            "refused: the anchor for %s occurs %d time(s), expected exactly 1.\n"
            "The upstream source is not the expected revision." % (what, n))
    return text.replace(old, new, 1)


def main():
    if len(sys.argv) < 2:
        print("usage: apply-lucy-obs.py <RTL812xLucy-commit-dir>")
        return 2
    root = sys.argv[1]
    drv = os.path.join(root, "RTL812xLucy")
    if not os.path.isdir(drv):
        print("refused: %s is not a driver directory" % drv)
        return 2

    hpp = os.path.join(drv, "RTL812xLucy.hpp")
    cpp = os.path.join(drv, "RTL812xLucy.cpp")
    for p in (hpp, cpp, HDR_SRC):
        if not os.path.isfile(p):
            print("refused: missing %s" % p)
            return 2

    cpp_text = read(cpp)
    hpp_text = read(hpp)
    # Idempotence: check BOTH files before touching either, so a half-applied
    # tree is detected instead of being patched a second time.
    if MARK_CPP in cpp_text or MARK_HPP in hpp_text:
        if MARK_CPP in cpp_text and MARK_HPP in hpp_text:
            print("already applied (the observation log is present)")
            return 0
        print("refused: the tree is HALF patched "
              "(cpp has the log: %s, hpp has it: %s). Re-extract the upstream "
              "source before applying." % (MARK_CPP in cpp_text,
                                           MARK_HPP in hpp_text))
        return 1

    # 1. the header
    hdr_dst = os.path.join(drv, "RTL812xObsLog.hpp")
    write(hdr_dst, read(HDR_SRC))
    print("wrote  %s" % hdr_dst)

    # 2. the class
    hpp_text = replace_once(hpp_text, HPP_INCLUDE_OLD, HPP_INCLUDE_NEW,
                            "the include block")
    hpp_text = replace_once(hpp_text, HPP_MEMBERS_OLD, HPP_MEMBERS_NEW,
                            "the flag members")
    write(hpp, hpp_text)
    print("patched %s" % hpp)

    # 3-8. the implementation
    cpp_text = replace_once(cpp_text, START_OLD, START_NEW, "start()")
    cpp_text = replace_once(cpp_text, STOP_OLD, STOP_NEW, "stop()")
    cpp_text = replace_once(cpp_text, TIMER_OLD, TIMER_NEW,
                            "timerActionRTL8125()")
    cpp_text = replace_once(cpp_text, OUTPUT_OLD, OUTPUT_NEW,
                            "outputStart() index advance")
    cpp_text = replace_once(cpp_text, OUTPUT_FILL_OLD, OUTPUT_FILL_NEW,
                            "outputStart() descriptor fill")
    cpp_text = replace_once(cpp_text, OUTPUT_DOORBELL_OLD, OUTPUT_DOORBELL_NEW,
                            "outputStart() doorbell")
    cpp_text = replace_once(cpp_text, TXDONE_OLD, TXDONE_NEW, "txInterrupt()")
    cpp_text = replace_once(cpp_text, RX_DECL_OLD, RX_DECL_NEW,
                            "rxInterrupt() declarations")
    cpp_text = replace_once(cpp_text, RX_CAPTURE_OLD, RX_CAPTURE_NEW,
                            "rxInterrupt() address capture")
    cpp_text = replace_once(cpp_text, RX_OLD, RX_NEW, "rxInterrupt() record")
    cpp_text = cpp_text.rstrip("\n") + "\n" + OBS_METHODS
    write(cpp, cpp_text)
    print("patched %s" % cpp)
    return 0


if __name__ == "__main__":
    sys.exit(main())
