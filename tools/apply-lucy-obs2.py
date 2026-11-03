#!/usr/bin/env python3
"""apply-lucy-obs2.py -- add the round-10 (version 2) observation log to a
pristine RTL812xLucy source tree.

WHY A PATCH SCRIPT RATHER THAN EDITED FILES IN THE WORKSPACE
-----------------------------------------------------------
The driver source is third-party (Laura Mueller, GPL-2.0, commit
639144d1f284a9fee222a518691b01494f5e265d). Keeping a hand-edited copy in the
workspace would make it impossible to tell, later, which bytes are upstream
and which are ours. This script applies named, individually described
insertions to a pristine tree and refuses to run twice, so the delta is
always reproducible from the upstream tarball.

WHAT CHANGED FROM ROUND 9 (see tools/lucy-obs/RTL812xObsLog.hpp for why)
-----------------------------------------------------------------------
  * the wire format is version 2 (72-byte record, self-describing 96-byte
    header inside the published blob)
  * obsWrite() is a real seqlock with an ownership re-check, so a body that
    was never written by one writer cannot be read as valid
  * obsPublish() emits ONE property containing header + records, so the
    header and the records cannot come from different publications
  * the header carries device identity (vendor/device/BDF/MAC/ifUnit), a
    driver-instance epoch and a publication id
  * records carry a business identifier (run token, request id, flow hash)
    extracted from the packet while the driver still holds the mbuf

WHAT IT ADDS, AND WHERE
-----------------------
  1. RTL812xObsLog.hpp              new file, the wire format
  2. RTL812xLucy.hpp                includes it; adds obsRegion/obsHdr/obsRecs
                                    members and the helper declarations
  3. RTL812xLucy.cpp  start()       allocates the log after setupStatResources()
  4. RTL812xLucy.cpp  stop()        publishes a last snapshot, then frees
  5. RTL812xLucy.cpp  outputStart() records every descriptor it fills, extracts
                                    the business id from the packet, records
                                    the doorbell
  6. RTL812xLucy.cpp  txInterrupt() records every descriptor handed back
  7. RTL812xLucy.cpp  rxInterrupt() records every descriptor it reaps and
                                    extracts the business id from the reply
  8. RTL812xLucy.cpp  new methods: obsInit/obsFree/obsWrite/obsPublish/
                                    obsParseBiz/obsPublishNow

The round-10--14 observation insertions only record/publish existing DMA.
Round 15 additionally exposes an opt-in finite owned RX allocation domain via
callPlatformFunction: Prepare freezes ordinary RX replacement and pre-exports
actual physical spans; Authorize permits at most 64 preallocated replacements
after the probe has completed mapping invalidations. No pool buffer is ever
delivered to the network stack or freed at Disarm. The AppleVTD/IOVM path is
explicitly unsupported by this physical-span API; ordinary operation is unchanged
until Prepare. Pool APIs never program a device register or an IOMMU mapping.

Round 16 adds an explicitly installed callback/context TX mapping ABI, limited
by token req1..4 and one in-flight slot. Real physical segments are passed after
coalescing and before any OWN; close-pointer completion only enqueues Retire.
A dedicated workloop timer retires mappings, then quarantines at most 4 mbufs
until explicit Disarm/drain/Detach. No probe discovery or identity fallback for
selected traffic. See tools/r16/driver-template.py and RTL812xTxMap.hpp.

Round 17 (selected with `--tx 17`) replaces that TX module with the native one:
the packet's own physical segments are mapped as they are (no staging copy, no
numSegs flattening), descriptors carry the returned non-identity IOVAs, and each
request's mbuf is released by its own retirement instead of being quarantined to
Detach. Evidence records and the command budget stay finite; the DMA owner does
not. See tools/r17/driver-template.py and RTL812xTxMapNative.hpp. The default
remains 16 so the archived round-16 build stays reproducible.

Round 33 keeps 1024 owned RX spares to standard mapper IOVAs
and reuses them cyclically until hold/disarm and drain restore the physical
ring buffers before standard unmap. It uses the dynamic TX arena and reserves
TX admission before dequeue. Its service-owned device domain survives the
setup worker. Select --tx 21 --rx 33 (--rx33 also works);
--rx 27..32 alias the same canonical cyclic template. The original physical
RX15 path remains the default.

Round 34 uses driver-owned virtual MD/command pairs for the normal RX
replaceOrCopyPacket path. Each completed slot unmaps before mbuf delivery and
remaps its current buffer before the next OWN store. Stop restores the current
physical ring before release. R15 remains a bootstrap allocation snapshot; its
spares do not participate in this receive path. Select --tx 21 --rx 34.

Usage:
    py -3 tools/apply-lucy-obs2.py <path-to-RTL812xLucy-commit-dir> [--tx 16..21] [--rx 15|27|28|29|30|31|32|33|34]
Exit 0 = applied (or already applied). Non-zero = refused, with the reason.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
HDR_SRC = os.path.join(HERE, "lucy-obs", "RTL812xObsLog.hpp")
# Round 11: the write/publish protocol lives in its own header so the host test
# can drive the very same code the driver runs. See that file's comment for
# the interleaving round 10's protocol could not survive.
WRITE_SRC = os.path.join(HERE, "lucy-obs", "RTL812xObsWrite.hpp")
# Round 14: the RX posted-buffer set -- a baseline of every descriptor's posted
# address/capacity plus a rearm log written at the hand-back site. Separate
# header for the same reason, plus one more: it is a different question from
# the observation log and must be judgeable on its own.
RXPOST_SRC = os.path.join(HERE, "lucy-obs", "RTL812xRxPost.hpp")
POOL_SRC = os.path.join(HERE, "lucy-obs", "RTL812xRxPool.hpp")
MARK_POOL = "RTL8125::r15PoolControl"

MARK_HPP = '#include "RTL812xObsLog.hpp"'
MARK_CPP = "RTL8125::obsWrite"
MARK_RXPOST = "RTL8125::rxpostCaptureBaseline"

# ---------------------------------------------------------------------------
# 2. RTL812xLucy.hpp
# ---------------------------------------------------------------------------
HPP_INCLUDE_OLD = '#include "RTL8125LucyRxPool.hpp"\n'
HPP_INCLUDE_NEW = ('#include "RTL8125LucyRxPool.hpp"\n'
                   '/* Round 10: bounded submit/complete metadata log (v2). */\n'
                   '#include "RTL812xObsLog.hpp"\n'
                   '/* Round 11: the write/publish protocol, shared with the\n'
                   ' * host regression test (tests/obs-write-test.cpp). */\n'
                   '#include "RTL812xObsWrite.hpp"\n'
                   '/* Round 14: the RX posted-buffer set (baseline + rearm log),\n'
                   ' * shared with the host regression test\n'
                   ' * (tests/rxpost-test.cpp). */\n'
                   '#include "RTL812xRxPost.hpp"\n')

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

    /* Round 10: the submit/complete observation log (wire version 2).
     *
     * This is the driver's own live memory object. The probe never maps it by
     * physical address: obsPublish() copies a suffix of it into an IORegistry
     * property, so a reader receives bytes the driver copied out of an object
     * it still holds.
     *
     * `obsSnap` is the staging buffer for one publication: it holds the
     * header FOLLOWED BY the records, and is published as a single OSData.
     * That is what makes header and records one immutable snapshot instead
     * of six properties that can tear against each other.
     */
    IOBufferMemoryDescriptor *obsRegion;
    RtlObsHdr *obsHdr;
    RtlObsRec *obsRecs;
    /* Publication staging: kObsHdrBytes + kObsPublishMax records = 36,960 B.
     * A member, not a local: that is far past the kernel stack. */
    UInt8 obsSnap[kObsSnapshotMax];
    UInt32 obsTxBatch;      /* first cumulative index of the packet being sent */
    UInt32 obsRxReaped;     /* cumulative count of reaped RX descriptors */
    UInt32 obsWrapped;      /* slots overwritten before being published */
    UInt32 obsDropped;      /* writers that lost their slot to another writer */
    UInt32 obsPubId;        /* publication counter, starts at 1 */
    UInt32 obsEpoch;        /* driver-instance epoch, seconds since boot */
    UInt32 obsBusDevFn;     /* (bus<<8)|(dev<<3)|fn of the PCI function */
    UInt32 obsVendorId;
    UInt32 obsDeviceId;
    UInt32 obsIfUnit;       /* BSD unit: 2 for en2 */
    UInt32 obsMacHi;
    UInt32 obsMacLo;

    bool     obsInit();
    void     obsFree();
    void     obsWrite(UInt32 kind, UInt32 cumulative, UInt32 slot, UInt32 gen,
                      UInt64 addr, UInt32 opts1, UInt32 opts2, UInt32 len,
                      UInt32 flags, UInt32 token, UInt32 reqId,
                      UInt32 flowHash, UInt32 pktFlags);
    void     obsPublish();
    void     obsPublishNow();
    UInt32   obsParseBiz(mbuf_t m, UInt32 len, bool isTx,
                         UInt32 *token, UInt32 *reqId, UInt32 *flowHash);

    /* ---- Round 14: the RX posted-buffer set ---------------------------
     *
     * `rxpostRegion` holds the header, BOTH slot arrays and the rearm ring.
     * The two slot arrays are what let a capture write while a publish copies:
     * the capture fills the INACTIVE one and flips `activeBaseline`, so a
     * publish never has to take the RX path's lock and a capture never has to
     * wait for a publish to finish.
     */
    IOBufferMemoryDescriptor *rxpostRegion;
    rxpost::Hdr *rxpostHdr;
    UInt8 *rxpostSlots[2];      /* the two slot arrays inside rxpostRegion */
    UInt8 *rxpostRearms;        /* the rearm ring inside rxpostRegion     */
    UInt8 rxpostSnap[kRxPostSnapshotMax];
    volatile unsigned int rxpostLock;   /* serialises rearm writers         */
    UInt32 rxpostWrapped;
    UInt32 rxpostDropped;
    UInt32 rxpostPubId;

    bool     rxpostInit();
    void     rxpostFree();
    void     rxpostCaptureBaseline();
    void     rxpostRecordRearm(UInt32 slot, UInt64 addr, UInt64 oldAddr,
                               UInt64 blenRaw);
    void     rxpostBumpGen();
    void     rxpostPublish();
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

    /* Round 10: allocate the observation log. A failure here is NOT fatal --
     * the NIC works fine without it, and refusing to start the interface
     * because a diagnostic buffer could not be allocated would be worse than
     * starting it with no diagnostics. obsInit() records the failure and
     * obsPublish() reports "unavailable" so the absence is visible. */
    if (!obsInit()) {
        IOLog("Observation log unavailable; continuing without it.\\n");
    }

    /* Round 14: the RX posted-buffer tables. Allocated AFTER setupRxResources()
     * because the first baseline capture reads rxDescArray/rxBufArray, and
     * before attachInterface() is not required (the BSD unit is resolved at
     * publish time). Not fatal, for the same reason as above. */
    if (!rxpostInit()) {
        IOLog("RX post tables unavailable; continuing without them.\\n");
    }
"""

STOP_OLD = """    freeStatResources();
    freeRxResources();
    freeTxResources();
"""
STOP_NEW = """    /* Round 10: publish a last snapshot, then release the log before the
     * rings it describes are torn down. Order matters: publishing after the
     * free would read a released buffer. */
    obsPublish();
    obsFree();

    /* Round 14: same ordering for the RX post tables -- the last publication
     * must describe the rings while they still exist. */
    rxpostCaptureBaseline();
    rxpostPublish();
    rxpostFree();

    freeStatResources();
    freeRxResources();
    freeTxResources();
"""

TIMER_OLD = """    rtl812xDumpTallyCounter(tp);
"""
TIMER_NEW = """    rtl812xDumpTallyCounter(tp);

    /* Round 14: refresh the RX posted-buffer baseline and publish it.
     *
     * WHY THE BASELINE IS RE-CAPTURED HERE AND NOT ONLY AT INIT
     * --------------------------------------------------------
     * The probe needs a baseline that is as close as possible to the moment
     * the window opens. A baseline captured at init() is minutes old by then,
     * and the ring has been re-posted many times. Re-capturing once a second
     * keeps the gap small; the rearm log covers whatever the gap still is,
     * which is why the two halves are joined on a watermark rather than on
     * time.
     *
     * WHY THIS IS SAFE ON THE WATCHDOG
     * --------------------------------
     * The watchdog is NOT assumed to be serialised with the RX path. The
     * capture only reads descriptor memory, the RX path only writes it, and
     * the read is a bounded retry pair -- see RTL812xRxPost.hpp. No lock is
     * taken here, so this cannot stall a packet path. */
    rxpostCaptureBaseline();
    rxpostPublish();

    /* Round 10: refresh the published observation log once per watchdog tick
     * (kTimerPeriod = 1 s). This is a PERIODIC refresh, not a barrier: the
     * snapshot a reader gets is the one that existed when it read the
     * property, and the header records tPublished so the reader can decide
     * for itself whether that snapshot covers the range it needs. Round 9
     * relied on "no more than a second old" and that is exactly what failed:
     * its snapshot was 0.53 s OLDER than the window end, so the window's last
     * half second was never in it. obsPublish() is a bounded memcpy plus one
     * property set; it does not touch the device.
     *
     * obsForcePublish lets a reader ask for a fresher snapshot than the last
     * tick produced, without that reader ever running the copy itself. */
    if (obsForcePublish) {
        obsForcePublish = false;
    }
    obsPublish();
"""

# ---------------------------------------------------------------------------
# Round 14: bump the RX ring generation at every path that rewrites descriptor
# addresses. A baseline captured under the old generation describes buffers
# that are no longer posted, so the join must refuse rather than mis-join.
# ---------------------------------------------------------------------------
SETUP_GEN_OLD = """void RTL8125::clearRxTxRings()
{
    IOMemoryDescriptor *md;
    mbuf_t m;
    UInt64 word1;
    UInt32 i;
"""
SETUP_GEN_NEW = """void RTL8125::clearRxTxRings()
{
    IOMemoryDescriptor *md;
    mbuf_t m;
    UInt64 word1;
    UInt32 i;

    /* Round 14: this function rewrites every RX descriptor address below, so
     * any baseline captured before it describes a ring that no longer exists.
     * Bumping the generation makes the invalidation explicit: the probe
     * requires the generation it saw before the window to equal the one in the
     * publication, and refuses the set if it moved. */
    rxpostBumpGen();
"""

VTD_GEN_OLD = """next_batch:
        /*
         * Update indices after every batch.
         */
        index = (index + kRxMemBatchSize) & kRxDescMask;
"""
VTD_GEN_NEW = """next_batch:
        /* Round 14: rxMapBuffers() has just rewritten kRxMemBatchSize
         * descriptor addresses, so the baseline is stale for that batch. */
        rxpostBumpGen();

        /*
         * Update indices after every batch.
         */
        index = (index + kRxMemBatchSize) & kRxDescMask;
"""

VTD_REARM_OLD = """    nextDesc:
        /*
         * If a batch has been completed, increment the number of
         * batches, which need to be mapped.
         */
        if ((rxNextDescIndex & kRxMemDescMask) == kRxMemDescMask)
            numMap++;
"""
VTD_REARM_NEW = """    nextDesc:
        /* Round 14: record the rearm on the VTD path too.
         *
         * This path does NOT re-program the descriptor here: the remap happens
         * later, in rxMapBuffers(), which also bumps the ring generation. So
         * `oldAddr == addr` here, and that is the HONEST value rather than a
         * placeholder -- the descriptor still names the same buffer at this
         * instant. The buffer that will eventually be retired by the remap is
         * not yet known at this point, so claiming to know it would be a guess.
         *
         * The remap itself is covered by the generation bump: a baseline
         * captured before it is refused, and the capture that follows it sees
         * the new addresses. Recording the rearm here still matters because the
         * rearm LOG is what proves the driver was recycling buffers during the
         * window; without it, `rearmRequired` would be 0 and the completeness
         * check would have nothing to check.
         *
         * Whether this path is live is exported as vtdPath; do not infer it
         * merely from the presence of an AppleVTD service. The captured round-14
         * target used the non-VTD path. */
        rxpostRecordRearm(rxNextDescIndex,
                          (UInt64)rxBufArray[rxNextDescIndex].phyAddr,
                          (UInt64)rxBufArray[rxNextDescIndex].phyAddr,
                          (UInt64)rxDescArray[rxNextDescIndex].buf.blen);

        /*
         * If a batch has been completed, increment the number of
         * batches, which need to be mapped.
         */
        if ((rxNextDescIndex & kRxMemDescMask) == kRxMemDescMask)
            numMap++;
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
        /* Round 10: remember where this packet starts in the cumulative index
         * space. txTailPtr0 is the driver's own submit counter, so
         * (txTailPtr0 + i) is the exact cumulative index of the i-th
         * descriptor of this packet -- the same number the hardware will
         * later report through the close pointer. */
        obsTxBatch = txTailPtr0;
        txTailPtr0 += numSegs;
        firstDesc = &txDescArray[index];
        lastSeg = numSegs - 1;

        /* Round 10: extract the business identifier ONCE for the whole
         * packet, while `m` is the mbuf we still hold. Every descriptor of
         * this packet then carries the same (token, reqId), so a multi-
         * segment packet cannot produce two records that disagree about
         * which request they belong to. */
        {
            UInt32 bizToken = 0, bizReq = 0, bizFlow = 0;
            obsPktFlags = obsParseBiz(m, (UInt32)mbuf_pkthdr_len(m), true,
                                      &bizToken, &bizReq, &bizFlow);
            obsPktToken = bizToken;
            obsPktReq = bizReq;
            obsPktFlow = bizFlow;
        }
"""

OUTPUT_FILL_OLD = """            desc->addr = OSSwapHostToLittleInt64(txSegments[i].location);
            desc->opts2 = OSSwapHostToLittleInt32(opts2);
            desc->opts1 = OSSwapHostToLittleInt32(opts1);
"""
OUTPUT_FILL_NEW = """            desc->addr = OSSwapHostToLittleInt64(txSegments[i].location);
            desc->opts2 = OSSwapHostToLittleInt32(opts2);
            desc->opts1 = OSSwapHostToLittleInt32(opts1);

            /* Round 10: record the descriptor exactly as it was programmed.
             * `len` is the real segment length (txSegments[i].length), which
             * is the one thing a reader of the ring cannot recover when the
             * descriptor carries a TSO command bit. `flags` says whether that
             * happened, so the length is never silently a guess.
             *
             * The business identifier is the SAME for every segment of this
             * packet (extracted once, above), so the join key is stable
             * across segments. */
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
                         oflags,
                         obsPktToken, obsPktReq, obsPktFlow, obsPktFlags);
            }
"""

OUTPUT_DOORBELL_OLD = """    /* Update tail pointer. */
    rtl812xDoorbell(&linuxData, txTailPtr0);
"""
OUTPUT_DOORBELL_NEW = """    /* Update tail pointer. */
    rtl812xDoorbell(&linuxData, txTailPtr0);

    /* Round 10: the doorbell is the moment the device is told the descriptors
     * exist. Recording it lets a reader separate "filled in" from "offered to
     * the device", which are two different claims. It carries the same
     * business id as the submits of the packet it releases. */
    obsWrite(kObsKindTxDoorbell, txTailPtr0, 0, 0, 0, 0, 0, 0, 0,
             obsPktToken, obsPktReq, obsPktFlow, obsPktFlags);
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

    /* Round 10: record each descriptor the device handed back, with the same
     * cumulative index the submit record used. A reader can therefore join
     * submit and completion on (cumulative) alone, without assuming anything
     * about slot reuse. `txClosePtr0` is the driver's own completion counter,
     * read from the hardware close pointer, so this is the same number that
     * produced numDone.
     *
     * The completion does NOT carry a business id: the mbuf has already been
     * unmapped and handed back by the time the close pointer advances, so
     * there is nothing left to parse. The join to a request goes
     * submit -> (cumulative) -> done, which is exact. */
    {
        UInt32 doneCum = txClosePtr0;
        UInt32 doneLeft = numDone;
        UInt32 doneIdx = txDirtyDescIndex;
        while (doneLeft-- > 0) {
            obsWrite(kObsKindTxDone,
                     doneCum,
                     doneIdx,
                     doneCum / kNumTxDesc,
                     0, 0, 0, 0, 0, 0, 0, 0, 0);
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

# The business id must be parsed while `rxPacketHead` still points at the
# completed packet. Round 10's first working attempt parsed it at `nextDesc`,
# where rxPacketHead has ALREADY been set to NULL two statements earlier -- so
# every RX record reported "short" and rx-parsed stayed 0 even though the four
# TX records parsed perfectly. That is a real defect: the reply existed, the
# identifier was in it, and the record said "could not read".
RX_BIZ_OLD = """            mbuf_pkthdr_setlen(rxPacketHead, rxPacketSize);
            interface->enqueueInputPacket(rxPacketHead, pollQueue);
"""

RX_BIZ_NEW = """            mbuf_pkthdr_setlen(rxPacketHead, rxPacketSize);

            /* Round 10: parse the business id HERE, while rxPacketHead still
             * points at the completed packet. The echo carries the same
             * (token, reqId) the TX submit did, so the reply can be joined to
             * its request by value. Doing this at nextDesc would be too late:
             * rxPacketHead is cleared immediately below. */
            obsRxToken = 0; obsRxReq = 0; obsRxFlow = 0;
            obsRxPktFlags = obsParseBiz(rxPacketHead,
                                        (UInt32)mbuf_pkthdr_len(rxPacketHead),
                                        false, &obsRxToken, &obsRxReq,
                                        &obsRxFlow);

            interface->enqueueInputPacket(rxPacketHead, pollQueue);
"""
RX_NEW = """        /* Finally update the descriptor and get the next one to examine. */
    nextDesc:
        /* Round 10: record the descriptor the device filled for us. `addr` is
         * the buffer the device wrote into, captured before re-programming
         * (obsRxAddr). `pktSize` is what the device reported.
         *
         * The business identifier is parsed from the received mbuf here, at
         * the only point where the driver still holds it. For the echo reply
         * this yields the SAME (token, reqId) that the TX submit carried, so
         * the reply can be joined to its request without using time or
         * addresses. */
        {
            /* Use the values captured where the packet was complete. */
            obsWrite(kObsKindRxDone,
                     obsRxReaped,
                     rxNextDescIndex,
                     obsRxReaped / kNumRxDesc,
                     obsRxAddr,
                     (UInt32)(descStatus1 & 0xFFFFFFFFu),
                     descStatus2,
                     (UInt32)pktSize,
                     (descStatus1 & RxRES) ? kObsFlagRxError : 0,
                     obsRxToken, obsRxReq, obsRxFlow, obsRxPktFlags);
        }
        obsRxReaped++;

        desc->buf.addr = OSSwapHostToLittleInt64(addr);
        desc->buf.blen = OSSwapHostToLittleInt64(word1);

        /* Round 14: record the buffer being handed BACK to the hardware.
         *
         * WHY HERE AND NOT NEXT TO THE obsWrite() ABOVE
         * ---------------------------------------------
         * This is the only point where the FINAL values are known. `addr` is
         * what the descriptor is being re-programmed with (either the original
         * buffer when `replaced` is false, or the new one installed by
         * replaceOrCopyPacket), and `word1` is the length word actually being
         * written. The observation log's rx-done record describes the buffer
         * the device just FILLED, and its `len` is the received packet size --
         * recording that as the posted capacity is exactly the substitution
         * this round exists to remove.
         *
         * WHY IT IS WRITTEN ON THE `nextDesc` PATH RATHER THAN IN THE SUCCESS
         * BRANCH: the error paths (RxRES, replaceOrCopyPacket failure, a
         * multi-segment mbuf) all jump here and all re-program the descriptor.
         * A rearm that only recorded the success path would understate the set
         * precisely where the driver is recycling buffers fastest.
         *
         * `obsRxAddr` is the buffer the descriptor posted at the TOP of this
         * iteration, i.e. exactly what this rearm retires. `addr` is what it
         * installs -- the same value when `replaced` is false, and the new
         * mbuf's physical address when it is true. Recording both is what keeps
         * a buffer that was live at the baseline instant from falling out of
         * the set when the rearm lands during the baseline scan. */
        rxpostRecordRearm(rxNextDescIndex, addr, obsRxAddr, word1);
"""

RX_CAPTURE_OLD = """    while (!((descStatus1 = OSSwapLittleToHostInt32(desc->cmd.opts1)) & DescOwn) && (goodPkts < maxCount)) {
        word1 = (rxNextDescIndex == kRxLastDesc) ? (kRxBufferSize | DescOwn | RingEnd) : (kRxBufferSize | DescOwn);
        addr = rxBufArray[rxNextDescIndex].phyAddr;
"""
RX_CAPTURE_NEW = """    while (!((descStatus1 = OSSwapLittleToHostInt32(desc->cmd.opts1)) & DescOwn) && (goodPkts < maxCount)) {
        word1 = (rxNextDescIndex == kRxLastDesc) ? (kRxBufferSize | DescOwn | RingEnd) : (kRxBufferSize | DescOwn);
        addr = rxBufArray[rxNextDescIndex].phyAddr;
        /* Round 10: the address the DEVICE wrote into, captured before the
         * descriptor is re-programmed below. */
        obsRxAddr = addr;
        /* Reset the business capture so this iteration cannot inherit the
         * previous packet's identity. */
        obsRxToken = 0; obsRxReq = 0; obsRxFlow = 0; obsRxPktFlags = 0;
"""

RX_DECL_OLD = """    UInt32 descStatus1, descStatus2;
    SInt32 pktSize;
    UInt32 goodPkts = 0;
    bool replaced;
"""
RX_DECL_NEW = """    /* Round 10: descStatus2 and pktSize are read on the RxRES path, which
     * jumps to nextDesc before assigning them. They were uninitialised there
     * before round 9; the observation record would have made that visible as
     * garbage rather than harmless, so they are now initialised. */
    UInt32 descStatus1, descStatus2 = 0;
    SInt32 pktSize = 0;
    UInt32 goodPkts = 0;
    bool replaced;
    UInt64 obsRxAddr = 0;
    /* Round 10: the business id of the packet completed in this iteration,
     * captured before rxPacketHead is cleared. Reset at the top of every
     * iteration so a packet without a magic never inherits the previous
     * packet's identity. */
    UInt32 obsRxToken = 0, obsRxReq = 0, obsRxFlow = 0, obsRxPktFlags = 0;
"""
OUTPUT_DECL_OLD = """    UInt32 lastSeg;
    UInt32 index;
    UInt32 i;
"""
OUTPUT_DECL_NEW = """    UInt32 lastSeg;
    UInt32 index;
    UInt32 i;
    /* Round 10: business identifier of the packet currently being filled.
     * Extracted once per packet, then copied into every segment's record, so
     * a multi-segment packet cannot produce two records that disagree about
     * which request they belong to. */
    UInt32 obsPktToken = 0, obsPktReq = 0, obsPktFlow = 0, obsPktFlags = 0;
"""

# RTL8125::getHardwareAddress(IOEthernetAddress *) already exists and returns
# the MAC the hardware is currently using, so no new plumbing is needed.
HPP_FORCE_MEMBER_OLD = """    UInt32 obsMacHi;
    UInt32 obsMacLo;
"""
HPP_FORCE_MEMBER_NEW = """    UInt32 obsMacHi;
    UInt32 obsMacLo;
    /* Set by obsPublishNow(); honoured by the next watchdog tick. */
    volatile bool obsForcePublish;
    /* Round 11: serialises obsWrite()'s claim/fill/publish sequence. See
     * RTL812xObsWrite.hpp -- round 10 preempted a slot that another writer was
     * still filling, which produced records whose body mixed two writers. */
    volatile unsigned int obsLock;
"""

# ---------------------------------------------------------------------------
# 8. the new methods, appended before the last line of the file
# ---------------------------------------------------------------------------
OBS_METHODS = r'''
#pragma mark --- round 10 observation log (wire version 2) ---

/* Allocate the log. Returns false when the buffer could not be created, in
 * which case every obsWrite() is a no-op and obsPublish() says so. */
bool RTL8125::obsInit()
{
    obsRegion = NULL;
    obsHdr = NULL;
    obsRecs = NULL;
    obsTxBatch = 0;
    obsRxReaped = 0;
    obsWrapped = 0;
    obsDropped = 0;
    obsPubId = 0;
    obsBusDevFn = 0;
    obsVendorId = 0;
    obsDeviceId = 0;
    obsIfUnit = 0;
    obsMacHi = 0;
    obsMacLo = 0;

    /* Epoch: seconds since boot at the moment this instance allocated the
     * log. A reader compares it against the snapshot's own value, so a
     * snapshot taken before a driver reload cannot be mistaken for one taken
     * after it. */
    obsForcePublish = false;
    obsLock = 0;
    {
        UInt64 ns = mach_absolute_time();
        obsEpoch = (UInt32)(ns / 1000000000ULL);
    }

    /* Device identity, taken from the IOPCIDevice this driver was matched
     * against and from the MAC the hardware is actually using. A snapshot
     * whose identity does not match the device under test is refused by the
     * reader instead of being silently attributed to it. */
    if (pciDevice) {
        UInt32 vd = pciDevice->configRead32(0);
        obsVendorId = vd & 0xFFFFu;
        obsDeviceId = (vd >> 16) & 0xFFFFu;
        UInt8 bus = pciDevice->getBusNumber() & 0xFFu;
        UInt8 dev = pciDevice->getDeviceNumber() & 0x1Fu;
        UInt8 fn  = pciDevice->getFunctionNumber() & 0x7u;
        obsBusDevFn = ((UInt32)bus << 8) | ((UInt32)dev << 3) | (UInt32)fn;
    }
    /* 【为什么 ifUnit 不能在 obsInit() 里定】
     *
     *   start() 里的顺序是：
     *       setupStatResources()  ->  obsInit()  ->  initEventSources()
     *       ->  attachInterface(&netif)
     *
     *   也就是说 obsInit() 运行时 netif 还是 NULL，取到的是 unit 0。
     *   第一版实机验证就是这样失败的：驱动快照头部写着 ifUnit = 0，
     *   而探针从 IORegistry 独立读到的是 2，身份核对报
     *   interface-unit-mismatch，整轮降级。
     *
     *   所以 ifUnit 改为在 obsPublish() 里现取（那时 attachInterface 早已
     *   完成），并且不只信 netif：先试 netif，再退回读父节点的
     *   IOInterfaceUnit 属性。两者都没有就留 0 并让读者判为不匹配——
     *   绝不猜一个看起来合理的数字。
     */
    obsIfUnit = 0;
    {
        /* getHardwareAddress() returns currMacAddr, i.e. the address the
         * hardware is actually using -- not the EEPROM default. That is the
         * one an operator can compare against ifconfig. */
        IOEthernetAddress ea;
        bzero(&ea, sizeof(ea));
        if (getHardwareAddress(&ea) == kIOReturnSuccess) {
            obsPackMac(ea.bytes, &obsMacHi, &obsMacLo);
        }
    }

    obsRegion = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(
        kernel_task,
        (kIODirectionOut | kIOMemoryPhysicallyContiguous |
         kIOMemoryHostPhysicallyContiguous),
        kObsRegionBytes,
        0xFFFFFFFFFFFFFF00ULL);

    if (!obsRegion) {
        IOLog("obsInit(): could not allocate the observation log.\n");
        return false;
    }
    if (obsRegion->prepare() != kIOReturnSuccess) {
        IOLog("obsInit(): prepare() failed.\n");
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
    obsHdr->recSize = kObsRecBytes;
    obsHdr->capacity = kObsCapacity;
    obsHdr->epoch = obsEpoch;
    obsHdr->tStart = mach_absolute_time();
    obsRecs = (RtlObsRec *)((UInt8 *)obsHdr + kObsHdrBytes);

    /* Publish once immediately, so a reader can tell "the log exists but is
     * empty" from "the log was never created". */
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
 * THE PROTOCOL (round 11 replaced round 10's; see RTL812xObsWrite.hpp)
 * --------------------------------------------------------------------
 * Round 10 claimed the slot with an unconditional atomic exchange and then
 * "re-checked ownership" before publishing. That re-check runs BEFORE the
 * last writer writes, so a writer whose slot was taken mid-body still
 * overwrites the new owner's fields and the new owner then stamps the
 * result. The surviving record is one writer's seq over two writers' bytes.
 * tools/r11/verify-write-protocol.py reproduces exactly that: 13 of 13 body
 * fields foreign.
 *
 * Round 11 holds a bounded spin lock across "claim ticket, claim slot, fill
 * body, publish", so the interleaving cannot occur rather than being detected
 * after the fact. The busy marker stays, because obsPublish() reads records
 * WITHOUT the lock (a ~37 KB memcpy under a spin lock would stall the output
 * thread) and needs a cheap "body in flight" signal.
 *
 * Everything here is bounded: kObsLockSpinMax retries, no sleeping, no
 * allocation. A writer that cannot take the lock increments `dropped`, which
 * reaches the published header, so a snapshot that lost records cannot
 * present itself as complete.
 */
void RTL8125::obsWrite(UInt32 kind, UInt32 cumulative, UInt32 slot, UInt32 gen,
                       UInt64 addr, UInt32 opts1, UInt32 opts2, UInt32 len,
                       UInt32 flags, UInt32 token, UInt32 reqId,
                       UInt32 flowHash, UInt32 pktFlags)
{
    if (!obsHdr || !obsRecs) return;
    /* Explicit opt-in scope BEFORE ticket claim: excluded load rows are not
     * dropped records or sequence holes. RXPOST and pool witnesses stay full. */
    if (!r15PoolObserve(kind, slot, token)) return;

    struct ObsFillCtx {
        UInt32 kind, cumulative, slot, gen;
        UInt64 addr;
        UInt32 opts1, opts2, len, flags, token, reqId, flowHash, pktFlags;
        UInt32 batch;
    } ctx;
    ctx.kind = kind;
    ctx.cumulative = cumulative;
    ctx.slot = slot;
    ctx.gen = gen;
    ctx.addr = addr;
    ctx.opts1 = opts1;
    ctx.opts2 = opts2;
    ctx.len = len;
    ctx.flags = flags;
    ctx.token = token;
    ctx.reqId = reqId;
    ctx.flowHash = flowHash;
    ctx.pktFlags = pktFlags;
    ctx.batch = obsTxBatch;

    const bool ok = obslog::writeRecord(
        &obsLock,
        (unsigned char *)obsHdr,
        (unsigned char *)obsRecs,
        kObsCapacityMask,
        [](unsigned char *rec, const ObsFillCtx &c) {
            RtlObsRec *r = (RtlObsRec *)rec;
            r->tMono = mach_absolute_time();
            r->addr = c.addr;
            r->kind = c.kind;
            r->cumulative = c.cumulative;
            r->slot = c.slot;
            r->gen = c.gen;
            r->batch = c.batch;
            r->opts1 = c.opts1;
            r->opts2 = c.opts2;
            r->len = c.len;
            r->flags = c.flags;
            r->token = c.token;
            r->reqId = c.reqId;
            r->flowHash = c.flowHash;
            r->pktFlags = c.pktFlags;
        },
        ctx,
        &obsDropped,
        &obsWrapped);

    if (!ok) {
        /* The loss is already in obsDropped, and obsPublish() copies it into
         * the published header's `dropped` field. Nothing else to do: a drop
         * must not be retried here, because the caller is on a packet path
         * that must not block. */
        IOLog("obsWrite(): dropped a record (lock bound exhausted).\n");
    }
}

/* Parse the business identifier out of a packet.
 *
 * Returns the kObsPkt* flags word. token/reqId/flowHash are set to 0 unless
 * kObsPktParsed is returned, so a caller can never see a half-decoded id.
 *
 * The parse is deliberately narrow: IPv4, IHL == 5, no fragmentation, no
 * VLAN, UDP, and the first four payload bytes equal kObsBizMagic. Anything
 * else is reported as "not parsed" with a reason. There is no fallback that
 * guesses an identifier from a length or a timestamp -- round 9 did exactly
 * that and it produced a claim that does not survive re-checking.
 */
UInt32 RTL8125::obsParseBiz(mbuf_t m, UInt32 len, bool isTx,
                            UInt32 *token, UInt32 *reqId, UInt32 *flowHash)
{
    *token = 0; *reqId = 0; *flowHash = 0;
    if (!m) return kObsPktShort;

    /* Bounded linearisation of the mbuf chain. Never more than
     * kObsBizScanMax bytes, never a copy into a variable-length buffer. */
    UInt8 buf[kObsBizScanMax];
    UInt32 have = 0;
    mbuf_t cur = m;
    while (cur && have < kObsBizScanMax) {
        const UInt32 segLen = (UInt32)mbuf_len(cur);
        const UInt8 *seg = (const UInt8 *)mbuf_data(cur);
        if (!seg) break;
        UInt32 take = segLen;
        if (take > kObsBizScanMax - have) take = kObsBizScanMax - have;
        memcpy(buf + have, seg, take);
        have += take;
        cur = mbuf_next(cur);
    }
    if (have < kObsBizHeaderBytes) return kObsPktShort;

    UInt32 flags = 0;
    UInt32 off = 12;                       /* after the two MACs */
    UInt16 etherType = ((UInt16)buf[off] << 8) | (UInt16)buf[off + 1];
    off += 2;
    if (etherType == 0x8100u || etherType == 0x88A8u) {
        /* VLAN tagged: the payload offset would depend on the tag stack, so
         * refuse rather than guess. */
        return kObsPktVlan;
    }
    if (etherType != 0x0800u) return kObsPktNotIpv4;

    if (have < off + 20u) return kObsPktShort;
    const UInt8 ihl = (UInt8)(buf[off] & 0x0Fu);
    const UInt16 fragField = ((UInt16)buf[off + 6] << 8) | (UInt16)buf[off + 7];
    const UInt8 proto = buf[off + 9];
    if (ihl != 5u) return kObsPktIpOptions;
    if ((fragField & 0x2000u) || (fragField & 0x1FFFu)) return kObsPktFragmented;
    if (proto != 17u) {
        /* TCP is explicitly out of scope: one write() is not one segment, so
         * an application-level id would need TCP sequence bookkeeping that
         * this driver does not have. */
        return (proto == 6u) ? kObsPktTcp : kObsPktNotUdp;
    }

    const UInt32 udpOff = off + 20u;
    if (have < udpOff + 8u) return kObsPktShort;
    const UInt16 udpLen = ((UInt16)buf[udpOff + 4] << 8) | (UInt16)buf[udpOff + 5];
    const UInt16 sport = ((UInt16)buf[udpOff] << 8) | (UInt16)buf[udpOff + 1];
    const UInt16 dport = ((UInt16)buf[udpOff + 2] << 8) | (UInt16)buf[udpOff + 3];

    const UInt32 payOff = udpOff + 8u;
    if (udpLen < 8u) return kObsPktTruncated;
    const UInt32 payLen = (UInt32)udpLen - 8u;
    if (payLen < 16u) return kObsPktShort;
    if (have < payOff + 16u) return kObsPktTruncated;

    const UInt32 magic = ((UInt32)buf[payOff] << 24) |
                         ((UInt32)buf[payOff + 1] << 16) |
                         ((UInt32)buf[payOff + 2] << 8) |
                         (UInt32)buf[payOff + 3];
    if (magic != kObsBizMagic) {
        (void)isTx;
        return kObsPktNoMagic;
    }
    const UInt32 t = ((UInt32)buf[payOff + 4] << 24) |
                      ((UInt32)buf[payOff + 5] << 16) |
                      ((UInt32)buf[payOff + 6] << 8) |
                      (UInt32)buf[payOff + 7];
    const UInt32 rq = ((UInt32)buf[payOff + 8] << 24) |
                       ((UInt32)buf[payOff + 9] << 16) |
                       ((UInt32)buf[payOff + 10] << 8) |
                       (UInt32)buf[payOff + 11];
    if (t == 0 || rq == 0) return kObsPktNoMagic;   /* 0 is never valid */

    /* Flow hash: ports plus the two IPv4 addresses, so two concurrent flows
     * with the same token are still distinguishable. */
    const UInt32 saddr = ((UInt32)buf[off + 12] << 24) |
                         ((UInt32)buf[off + 13] << 16) |
                         ((UInt32)buf[off + 14] << 8) |
                         (UInt32)buf[off + 15];
    const UInt32 daddr = ((UInt32)buf[off + 16] << 24) |
                         ((UInt32)buf[off + 17] << 16) |
                         ((UInt32)buf[off + 18] << 8) |
                         (UInt32)buf[off + 19];
    UInt32 h = 2166136261u;
    h = (h ^ (UInt32)sport) * 16777619u;
    h = (h ^ (UInt32)dport) * 16777619u;
    h = (h ^ saddr) * 16777619u;
    h = (h ^ daddr) * 16777619u;

    *token = t;
    *reqId = rq;
    *flowHash = h;
    flags |= kObsPktParsed;
    (void)len;
    return flags;
}

/* Publish one self-describing snapshot: header + records in ONE OSData.
 *
 * WHY ONE PROPERTY
 * ----------------
 * Round 9 published head/first/published/wrapped/t-published as five OSString
 * properties and the records as a sixth OSData property. Each individual
 * property write is atomic, but the six together are not, so a reader could
 * pair a header from publication N with records from publication N-1. Round
 * 9's own archive shows two different publications 87 s apart, and the report
 * used the later one as if it were the earlier one.
 *
 * Here the header travels WITH the records. There is one property to read, so
 * there is nothing to tear. `pubId` increments on every publish, so a reader
 * can also detect that two reads returned the same snapshot (or not).
 */
void RTL8125::obsPublish()
{
    if (!obsHdr || !obsRecs) {
        setProperty("rtl812x-obs-state", "unavailable");
        setProperty("rtl812x-obs-format", kObsFormat);
        return;
    }

    RtlObsHdr *snap = (RtlObsHdr *)obsSnap;
    RtlObsRec *snapRecs = (RtlObsRec *)(obsSnap + kObsHdrBytes);

    const UInt64 now = mach_absolute_time();
    /* head counts tickets ISSUED, and tickets start at 1, so the last
     * issued ticket is exactly head. */
    const UInt32 head = __atomic_load_n(&obsHdr->head, __ATOMIC_ACQUIRE);
    UInt32 n = (head < kObsPublishMax) ? head : kObsPublishMax;
    const UInt32 firstTicket = head - n + 1u;   /* ticket of the first copied */

    UInt32 copied = 0, lost = 0;
    UInt32 lastTicket = firstTicket;   /* overwritten by the last good copy */
    /* Round 11: the copy itself lives in RTL812xObsWrite.hpp, so the host test
     * exercises the same code the driver runs. The publisher deliberately does
     * NOT take the write lock: a ~37 KB memcpy under a spin lock would stall
     * every writer. It relies on the busy marker plus the double read, which
     * the locked writer makes reliable. */
    obslog::publishCopy((const unsigned char *)obsRecs,
                        kObsCapacityMask,
                        kObsCapacity,
                        firstTicket,
                        n,
                        (unsigned char *)snapRecs,
                        kObsRecBytes,
                        &copied,
                        &lost);
    if (n > 0) lastTicket = firstTicket + n - 1u;

    /* Resolve the BSD unit NOW, not in obsInit(): start() calls obsInit()
     * before attachInterface(), so netif is still NULL there. */
    {
        UInt32 unit = 0;
        bool have = false;
        if (netif) {
            unit = (UInt32)netif->getUnitNumber();
            have = true;
        }
        if (!have) {
            OSNumber *u = OSDynamicCast(OSNumber,
                                        copyProperty("IOInterfaceUnit"));
            if (u) {
                unit = (UInt32)u->unsigned32BitValue();
                have = true;
                u->release();
            }
        }
        if (have) obsIfUnit = unit;
    }

    obsPubId++;

    snap->magic       = kObsMagic;
    snap->version     = kObsVersion;
    snap->recSize     = kObsRecBytes;
    snap->capacity    = kObsCapacity;
    snap->head        = head;
    snap->wrapped     = obslog::readLoss(&obsWrapped);
    snap->dropped     = obslog::readLoss(&obsDropped);
    snap->pubId       = obsPubId;
    snap->firstTicket = firstTicket;
    snap->lastTicket  = lastTicket;
    snap->validCount  = n - lost;
    snap->lostCount   = lost;
    snap->epoch       = obsEpoch;
    snap->busDevFn    = obsBusDevFn;
    snap->vendorId    = obsVendorId;
    snap->deviceId    = obsDeviceId;
    snap->ifUnit      = obsIfUnit;
    snap->macHi       = obsMacHi;
    snap->macLo       = obsMacLo;
    snap->flags       = 0;
    if (head > kObsCapacity) snap->flags |= kObsHdrFlagOverflowed;
    if (lost)                snap->flags |= kObsHdrFlagLost;
    /* Round 12: a writer that never got a ticket leaves no hole in the ticket
     * range, so the reader cannot see it from the records. It MUST reach the
     * header, or a snapshot that lost records reports itself as complete. */
    if (snap->dropped != 0)  snap->flags |= kObsHdrFlagLost;
    if (head > n)            snap->flags |= kObsHdrFlagTruncated;
    snap->tStart      = obsHdr->tStart;
    snap->tPublished  = now;
    snap->reserved    = 0;

    const UInt32 bytes = kObsHdrBytes + n * kObsRecBytes;
    OSData *blob = OSData::withBytes(obsSnap, bytes);
    if (blob) {
        setProperty("rtl812x-obs-snapshot", blob);
        blob->release();
    }

    /* Non-authoritative convenience strings. A reader MUST use the header
     * inside rtl812x-obs-snapshot; these exist only so a human looking at
     * ioreg can see the state at a glance. They are deliberately named
     * differently from v1's so a v1 reader cannot mistake them for its own. */
    setProperty("rtl812x-obs-format", kObsFormat);
    setProperty("rtl812x-obs-state",
                (lost || obslog::readLoss(&obsDropped)) ? "degraded" : "ok");
    /* Round 11: publish the instance epoch as its own property as well as in
     * the snapshot header. A reader that needs to bind to "this driver
     * instance" BEFORE it reads a snapshot (because binding from the snapshot
     * it is about to judge would be circular) needs a channel that is not the
     * snapshot. The probe reads this one at step 15c, before the window. */
    {
        OSNumber *en = OSNumber::withNumber((unsigned long long)obsEpoch, 32);
        if (en) {
            setProperty("rtl812x-obs-epoch", en);
            en->release();
        }
    }
}

/* Publish on demand. Exposed so the probe's reader can ask for a fresh
 * snapshot instead of using whatever the last watchdog tick left behind.
 *
 * BOUNDED: this only sets a flag that the next watchdog tick honours. It does
 * NOT block, does NOT wait for the tick, and does NOT call obsPublish()
 * directly from another thread's context -- doing so would run a ~37 KiB
 * memcpy on the caller's thread while the output thread is writing records,
 * and would put an unbounded delay inside the probe's measurement window.
 * The reader is expected to poll the publication id with a bounded deadline
 * and to DEGRADE if a fresh-enough snapshot does not appear. */
void RTL8125::obsPublishNow()
{
    obsForcePublish = true;
}
'''

# ---------------------------------------------------------------------------
# Round 14: the RX posted-buffer set
# ---------------------------------------------------------------------------
RXPOST_METHODS = r'''
#pragma mark --- round 14 RX posted-buffer set ---
/* Allocate the RX posted-buffer tables and capture the first baseline.
 *
 * A failure here is NOT fatal: the NIC works without it and refusing to start
 * the interface because a diagnostic buffer could not be allocated would be
 * worse. The header's `flags` carries NO_BASELINE so the absence is visible
 * instead of being read as "the set is empty".
 */
bool RTL8125::rxpostInit()
{
    rxpostRegion = NULL;
    rxpostHdr = NULL;
    rxpostSlots[0] = rxpostSlots[1] = NULL;
    rxpostRearms = NULL;
    rxpostLock = 0;
    rxpostWrapped = 0;
    rxpostDropped = 0;
    rxpostPubId = 0;

    /* The wire constants are duplicated in RTL812xRxPost.hpp so the host test
     * can compile without the driver's headers. Assert them against the real
     * enumerators here: a drift would silently decode DescOwn as a length. */
    static_assert(kRxPostSlots == kNumRxDesc,
                  "the slot table must be exactly one record per descriptor");
    static_assert(kRxPostDescOwn == (UInt32)DescOwn,
                  "kRxPostDescOwn must be the driver's DescOwn");
    static_assert(kRxPostRingEnd == (UInt32)RingEnd,
                  "kRxPostRingEnd must be the driver's RingEnd");
    /* THE TIE THAT WOULD HAVE CAUGHT THE PANIC.
     *
     * kRxPostRegionBytes is computed from kRxPostSlotTables, so changing that
     * constant moves the size and the offset together and the header's own
     * assertions still pass. This one compares the macro against the ARRAY THE
     * DRIVER ACTUALLY DECLARES. With `rxpostSlots[2]` and a macro saying 1, the
     * region came out one slot array short and the tail of the rearm ring fell
     * outside the mapping -- a page fault on write, minutes later. */
    static_assert(sizeof(rxpostSlots) / sizeof(rxpostSlots[0]) ==
                      kRxPostSlotTables,
                  "kRxPostSlotTables must equal the number of slot arrays "
                  "the driver declares");

    rxpostRegion = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(
        kernel_task,
        (kIODirectionOut | kIOMemoryPhysicallyContiguous |
         kIOMemoryHostPhysicallyContiguous),
        (vm_size_t)kRxPostRegionBytes,
        0xFFFFFFFFFFFFFF00ULL);
    if (!rxpostRegion) {
        IOLog("rxpostInit(): could not allocate the RX post tables.\n");
        return false;
    }
    if (rxpostRegion->prepare() != kIOReturnSuccess) {
        IOLog("rxpostInit(): prepare() failed.\n");
        rxpostRegion->release();
        rxpostRegion = NULL;
        return false;
    }
    rxpostHdr = (rxpost::Hdr *)rxpostRegion->getBytesNoCopy();
    if (!rxpostHdr) {
        rxpostRegion->complete();
        rxpostRegion->release();
        rxpostRegion = NULL;
        return false;
    }
    bzero(rxpostHdr, (size_t)kRxPostRegionBytes);

    rxpostSlots[0] = (UInt8 *)rxpostHdr + kRxPostHdrBytes;
    rxpostSlots[1] = rxpostSlots[0] + (UInt64)kRxPostSlots * kRxPostSlotBytes;
    rxpostRearms   = rxpostSlots[1] + (UInt64)kRxPostSlots * kRxPostSlotBytes;

    /* THE RING MUST LIE ENTIRELY INSIDE THE ALLOCATION.
     *
     * Round 14's run 5 panicked here, ~242 s in: `kRxPostRegionBytes` was
     * `kRxPostSnapshotMax`, which counts ONE slot array, while the layout above
     * places the ring after TWO. The tail of the ring therefore fell outside the
     * IOBufferMemoryDescriptor's mapping, and the fault only appeared once the
     * ring filled far enough -- which is why it survived the experiment itself
     * and killed the machine minutes later.
     *
     * The static_asserts in RTL812xRxPost.hpp now tie the macro to this layout.
     * This second check is not redundant: it compares against the buffer the
     * allocator ACTUALLY returned. If IOBufferMemoryDescriptor rounds the size
     * DOWN, or a future edit sizes the macro from a different expression than
     * the one asserted, the compile-time check still passes and this one does
     * not. A diagnostic table is never worth a panic, so on a mismatch the
     * tables are abandoned rather than used. */
    {
        const UInt8 *base = (const UInt8 *)rxpostHdr;
        const UInt64 end  = (UInt64)(rxpostRearms - base) +
                            (UInt64)kRxPostRearmCap * kRxPostRearmBytes;
        const UInt64 have = (UInt64)kRxPostRegionBytes;
        if (end > have ||
            (UInt64)(rxpostRegion->getLength()) < have) {
            IOLog("rxpostInit(): ring end %llu exceeds region %llu (have %llu);"
                  " refusing to use the tables.\\n",
                  end, have, (UInt64)rxpostRegion->getLength());
            rxpostRegion->complete();
            rxpostRegion->release();
            rxpostRegion = NULL;
            rxpostHdr = NULL;
            rxpostSlots[0] = rxpostSlots[1] = NULL;
            rxpostRearms = NULL;
            return false;
        }
    }

    rxpostHdr->magic         = kRxPostMagic;
    rxpostHdr->version       = kRxPostVersion;
    rxpostHdr->recSizeSlot   = kRxPostSlotBytes;
    rxpostHdr->recSizeRearm  = kRxPostRearmBytes;
    rxpostHdr->slotCapacity  = kRxPostSlots;
    rxpostHdr->rearmCapacity = kRxPostRearmCap;
    rxpostHdr->rxBufferSize  = (UInt32)kRxBufferSize;
    rxpostHdr->ringGen       = 1;
    rxpostHdr->epoch         = obsEpoch;
    rxpostHdr->flags         = kRxPostHdrFlagNoBaseline;

    /* Capture once immediately, so a reader can tell "the tables exist but the
     * ring was not ready" from "the tables were never created". */
    rxpostCaptureBaseline();
    rxpostPublish();
    return true;
}

void RTL8125::rxpostFree()
{
    if (rxpostRegion) {
        rxpostRegion->complete();
        rxpostRegion->release();
        rxpostRegion = NULL;
    }
    rxpostHdr = NULL;
    rxpostSlots[0] = rxpostSlots[1] = NULL;
    rxpostRearms = NULL;
}

/* Bump the ring generation. Called from EVERY path that rewrites descriptor
 * addresses, because a baseline captured under the old generation describes
 * buffers that are no longer posted. A reader requires the generation to
 * match, so this turns "the ring was rebuilt" into an explicit invalidation
 * rather than a silent mis-join. */
void RTL8125::rxpostBumpGen()
{
    r15PoolInvalidate();
    if (!rxpostHdr) return;
    __atomic_fetch_add(&rxpostHdr->ringGen, 1u, __ATOMIC_RELAXED);
    /* The baseline is now known-stale. The next capture replaces it; until
     * then the header says so instead of describing the old ring. */
    __atomic_store_n(&rxpostHdr->baselineSlots, 0u, __ATOMIC_RELAXED);
    __atomic_store_n(&rxpostHdr->flags,
                     __atomic_load_n(&rxpostHdr->flags, __ATOMIC_RELAXED) |
                         kRxPostHdrFlagNoBaseline,
                     __ATOMIC_RELAXED);
}

/* Capture the baseline: every descriptor's posted address and capacity.
 *
 * WHY THE WATERMARK IS READ FIRST
 * -------------------------------
 * See RTL812xRxPost.hpp rule 1. Reading it after the scan would let a rearm
 * that happened DURING the scan be excluded from the required set while also
 * being invisible in the scan, and the address it replaced would then be in
 * neither half.
 *
 * WHY A BOUNDED RETRY PER SLOT
 * ----------------------------
 * The RX path writes `buf.addr` then `buf.blen`. A reader that takes `blen`,
 * then `addr`, then `blen` again and sees the same `blen` twice has either a
 * consistent pair or an `addr` that is NEWER than the length -- and "newer
 * address with an older length word" describes the buffer being posted right
 * now, which is conservative for a set that must be a superset. The retry
 * exists to catch the case where `blen` changed, and a pair that never
 * stabilises is counted (`baselineTorn`) rather than published as if it were
 * read cleanly.
 *
 * WHY IT IS SAFE TO CALL FROM THE WATCHDOG
 * ----------------------------------------
 * The watchdog is not assumed to be serialised with the RX path -- that
 * assumption is exactly what this round refuses to make. The scan only READS
 * descriptor memory, and the RX path only WRITES it, so there is no ordering
 * requirement beyond the bounded retry above. The two slot arrays mean a
 * publish that is copying one array cannot see a capture writing it.
 */
void RTL8125::rxpostCaptureBaseline()
{
    if (!rxpostHdr || !rxpostSlots[0] || !rxDescArray || !rxBufArray) return;

    /* Rule 1: the watermark BEFORE the scan. */
    const UInt32 headBefore =
        __atomic_load_n(&rxpostHdr->head, __ATOMIC_ACQUIRE);
    const UInt32 genBefore =
        __atomic_load_n(&rxpostHdr->ringGen, __ATOMIC_RELAXED);

    /* The capture always writes the array the publisher is NOT reading, then
     * flips `baselineActive`. That flip is the only cross-context write the
     * capture makes, so a publish that is copying one array can never see a
     * capture writing it. */
    const UInt32 useIdx =
        __atomic_load_n(&rxpostHdr->baselineActive, __ATOMIC_RELAXED) ^ 1u;
    UInt8 *dst = rxpostSlots[useIdx];

    UInt32 slots = 0, valid = 0, addrZero = 0, capDesc = 0, capConst = 0;
    UInt32 capBad = 0, torn = 0;

    for (UInt32 i = 0; i < kNumRxDesc; i++) {
        const UInt64 a0 = (UInt64)rxDescArray[i].buf.addr;
        const UInt64 b0 = (UInt64)rxDescArray[i].buf.blen;
        const UInt64 b1 = (UInt64)rxDescArray[i].buf.blen;
        const UInt64 a1 = (UInt64)rxDescArray[i].buf.addr;
        const UInt64 b2 = (UInt64)rxDescArray[i].buf.blen;

        UInt64 addr = a0;
        UInt64 blen = b0;
        UInt32 extra = 0;
        if (b1 != b0 || b2 != b0) {
            /* The length word moved under the read. Take the last pair and
             * say so: a torn pair is still a POSTED buffer (the device will be
             * told about it), so dropping it would understate the set. */
            extra |= kRxPostSlotTorn;
            torn++;
            addr = a1;
            blen = b2;
        }

        rxpost::fillSlotRec(dst + (UInt64)i * kRxPostSlotBytes,
                            i, addr, blen, genBefore,
                            (UInt32)kRxBufferSize, extra);

        const rxpost::SlotRec *r =
            (const rxpost::SlotRec *)(dst + (UInt64)i * kRxPostSlotBytes);
        slots++;
        if (r->flags & kRxPostSlotAddrZero) addrZero++; else valid++;
        if (r->flags & kRxPostSlotCapFromDesc) capDesc++;
        if (r->flags & kRxPostSlotCapFromConst) capConst++;
        if (r->flags & kRxPostSlotCapMismatch) capBad++;
    }

    /* Rule 3: if the ring was rebuilt while we scanned, the scan describes two
     * different rings. Throw it away rather than publish a mixture. */
    const UInt32 genAfter =
        __atomic_load_n(&rxpostHdr->ringGen, __ATOMIC_RELAXED);
    if (genAfter != genBefore) {
        __atomic_fetch_add(&rxpostHdr->baselineGenMoved, 1u, __ATOMIC_RELAXED);
        __atomic_store_n(&rxpostHdr->baselineSlots, 0u, __ATOMIC_RELAXED);
        __atomic_store_n(&rxpostHdr->flags,
                         __atomic_load_n(&rxpostHdr->flags, __ATOMIC_RELAXED) |
                             kRxPostHdrFlagNoBaseline,
                         __ATOMIC_RELAXED);
        return;
    }

    __atomic_store_n(&rxpostHdr->baselineSlots, slots, __ATOMIC_RELAXED);
    __atomic_store_n(&rxpostHdr->baselineValid, valid, __ATOMIC_RELAXED);
    __atomic_store_n(&rxpostHdr->baselineAddrZero, addrZero, __ATOMIC_RELAXED);
    __atomic_store_n(&rxpostHdr->baselineCapDesc, capDesc, __ATOMIC_RELAXED);
    __atomic_store_n(&rxpostHdr->baselineCapConst, capConst, __ATOMIC_RELAXED);
    __atomic_store_n(&rxpostHdr->baselineCapBad, capBad, __ATOMIC_RELAXED);
    __atomic_store_n(&rxpostHdr->baselineTorn, torn, __ATOMIC_RELAXED);
    __atomic_fetch_add(&rxpostHdr->baselineCount, 1u, __ATOMIC_RELAXED);
    __atomic_store_n(&rxpostHdr->rearmFirstSeq,
                     rxpost::firstSeqFor(headBefore, kRxPostRearmCap),
                     __ATOMIC_RELAXED);
    __atomic_store_n(&rxpostHdr->rearmSeqAtBaseline, (UInt32)headBefore,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&rxpostHdr->tBaseline, mach_absolute_time(),
                     __ATOMIC_RELAXED);

    /* Flip the published index, then clear the NO_BASELINE flag. Order
     * matters: a publisher that reads the new index must find a complete
     * array behind it, and it reads the flag after the index. */
    __atomic_store_n(&rxpostHdr->baselineActive, useIdx, __ATOMIC_RELAXED);
    __atomic_store_n(&rxpostHdr->flags,
                     __atomic_load_n(&rxpostHdr->flags, __ATOMIC_RELAXED) &
                         ~(UInt32)kRxPostHdrFlagNoBaseline,
                     __ATOMIC_RELAXED);
}

/* Record one rearm: the driver is handing `slot` back to the hardware with
 * `addr` and `blenRaw` as the FINAL descriptor words, retiring `oldAddr`.
 *
 * Called from the hand-back site, i.e. where the descriptor is actually
 * re-programmed, so the values recorded are the ones the device will use. The
 * observation log's rx-done record is NOT reused: its `len` is the received
 * packet size, and substituting that for the posted capacity is precisely the
 * defect this round exists to remove.
 *
 * WHY `oldAddr` IS A PARAMETER AND NOT READ HERE
 * ----------------------------------------------
 * The caller is the only one that knows which buffer is being retired: on the
 * `replaced` path the old buffer came from `replaceOrCopyPacket`, and on the
 * non-replaced path the buffer is unchanged (old == new). Reading it here from
 * the descriptor would give the address that is being INSTALLED, which is the
 * bug this field exists to prevent.
 */
void RTL8125::rxpostRecordRearm(UInt32 slot, UInt64 addr, UInt64 oldAddr,
                                UInt64 blenRaw)
{
    if (!rxpostHdr || !rxpostRearms) return;

    struct RxPostFillCtx {
        UInt32 slot;
        UInt64 addr;
        UInt64 oldAddr;
        UInt64 blenRaw;
        UInt64 tMono;
        UInt32 extra;
    } ctx;
    ctx.slot = slot;
    ctx.addr = addr;
    ctx.oldAddr = oldAddr;
    ctx.blenRaw = blenRaw;
    ctx.tMono = mach_absolute_time();
    ctx.extra = (oldAddr != addr) ? kRxPostRearmReplaced : 0u;

    obslog::writeRecordSized(
        &rxpostLock,
        (unsigned char *)rxpostHdr,
        (unsigned char *)rxpostRearms,
        kRxPostRearmMask,
        kRxPostRearmBytes,
        kRxPostRearmSeqWord,
        [](unsigned char *rec, const RxPostFillCtx &c) {
            rxpost::fillRearmRec(rec, c.slot, c.addr, c.oldAddr, c.blenRaw,
                                 c.tMono, c.extra);
        },
        ctx,
        &rxpostDropped,
        &rxpostWrapped);
}

/* Publish one self-describing blob: header, the slot array, the rearm ring. */
void RTL8125::rxpostPublish()
{
    if (!rxpostHdr || !rxpostSlots[0] || !rxpostRearms) {
        setProperty("rtl812x-rxpost-state", "unavailable");
        setProperty("rtl812x-rxpost-format", kRxPostFormat);
        return;
    }

    rxpost::Hdr *snap = (rxpost::Hdr *)rxpostSnap;
    const UInt32 head = __atomic_load_n(&rxpostHdr->head, __ATOMIC_ACQUIRE);
    const UInt32 watermark =
        __atomic_load_n(&rxpostHdr->rearmSeqAtBaseline, __ATOMIC_RELAXED);

    /* Publish the NEWEST records the budget allows, not merely the ones this
     * instance's own baseline needs.
     *
     * WHY: the probe takes its baseline BEFORE the window and reads the rearm
     * log AFTER it, so the records it requires start at ITS watermark, which is
     * older than any baseline this driver captures afterwards. Publishing only
     * "from my own watermark" would make the probe's older watermark
     * unrepresentable. Publishing the newest N lets the probe check the one
     * thing that matters -- whether the ring still holds records back to its
     * watermark -- instead of depending on when this instance last captured.
     */
    UInt32 want = head;

    /* Read the index AFTER the watermark and AFTER the head: the capture sets
     * the index last, so an index read here names an array that was complete
     * when it was flipped. */
    const UInt32 useIdx =
        __atomic_load_n(&rxpostHdr->baselineActive, __ATOMIC_RELAXED);
    const UInt8 *slotBase = rxpostSlots[useIdx & 1u];

    UInt32 published = 0;
    const UInt32 bytes = rxpost::publishCopy(
        slotBase, (const UInt8 *)rxpostRearms, head, want,
        kRxPostRearmCap, kRxPostRearmMask,
        (unsigned char *)snap, &published);

    UInt32 pubId = __atomic_load_n(&rxpostHdr->pubId, __ATOMIC_RELAXED) + 1u;
    __atomic_store_n(&rxpostHdr->pubId, pubId, __ATOMIC_RELAXED);

    /* Resolve the BSD unit now: rxpostInit() runs before attachInterface(). */
    if (netif) {
        __atomic_store_n(&rxpostHdr->ifUnit,
                         (UInt32)netif->getUnitNumber(), __ATOMIC_RELAXED);
    }

    snap->magic              = kRxPostMagic;
    snap->version            = kRxPostVersion;
    snap->recSizeSlot        = kRxPostSlotBytes;
    snap->recSizeRearm       = kRxPostRearmBytes;
    snap->head               = head;
    snap->wrapped            = obslog::readLoss(&rxpostWrapped);
    snap->dropped            = obslog::readLoss(&rxpostDropped);
    snap->slotCapacity       = kRxPostSlots;
    snap->rearmCapacity      = kRxPostRearmCap;
    snap->rearmFirstSeq      = published ? (head - published + 1u) : 0u;
    snap->ringGen            = __atomic_load_n(&rxpostHdr->ringGen,
                                               __ATOMIC_RELAXED);
    snap->baselineSlots      = __atomic_load_n(&rxpostHdr->baselineSlots,
                                               __ATOMIC_RELAXED);
    snap->baselineValid      = __atomic_load_n(&rxpostHdr->baselineValid,
                                               __ATOMIC_RELAXED);
    snap->baselineAddrZero   = __atomic_load_n(&rxpostHdr->baselineAddrZero,
                                               __ATOMIC_RELAXED);
    snap->baselineCapDesc    = __atomic_load_n(&rxpostHdr->baselineCapDesc,
                                               __ATOMIC_RELAXED);
    snap->baselineCapConst   = __atomic_load_n(&rxpostHdr->baselineCapConst,
                                               __ATOMIC_RELAXED);
    snap->baselineCapBad     = __atomic_load_n(&rxpostHdr->baselineCapBad,
                                               __ATOMIC_RELAXED);
    snap->baselineTorn       = __atomic_load_n(&rxpostHdr->baselineTorn,
                                               __ATOMIC_RELAXED);
    snap->baselineCount      = __atomic_load_n(&rxpostHdr->baselineCount,
                                               __ATOMIC_RELAXED);
    snap->baselineGenMoved   = __atomic_load_n(&rxpostHdr->baselineGenMoved,
                                               __ATOMIC_RELAXED);
    snap->pubId              = pubId;
    snap->epoch              = obsEpoch;
    snap->ifUnit             = __atomic_load_n(&rxpostHdr->ifUnit,
                                               __ATOMIC_RELAXED);
    snap->vtdPath            = __atomic_load_n(&rxpostHdr->vtdPath,
                                               __ATOMIC_RELAXED) & 1u;
    snap->rxBufferSize       = (UInt32)kRxBufferSize;
    snap->rearmRequired      = want;
    snap->rearmPublished     = published;
    snap->tBaseline          = __atomic_load_n(&rxpostHdr->tBaseline,
                                               __ATOMIC_RELAXED);
    snap->rearmSeqAtBaseline = watermark;
    snap->tPublished         = mach_absolute_time();

    snap->flags = 0;
    if (__atomic_load_n(&rxpostHdr->baselineSlots, __ATOMIC_RELAXED) == 0)
        snap->flags |= kRxPostHdrFlagNoBaseline;
    if (snap->dropped != 0 || snap->wrapped != 0)
        snap->flags |= kRxPostHdrFlagRearmLost;
    if (__atomic_load_n(&rxpostHdr->baselineGenMoved, __ATOMIC_RELAXED) != 0)
        snap->flags |= kRxPostHdrFlagGenMoved;
    /* A prefix is NOT a complete answer. Say so, in the header, where the
     * reader looks -- never only in a comment next to the copy loop. */
    if (published < want)
        snap->flags |= kRxPostHdrFlagTruncated;

    OSData *blob = OSData::withBytes(rxpostSnap, bytes);
    if (blob) {
        setProperty("rtl812x-rxpost", blob);
        blob->release();
    }
    setProperty("rtl812x-rxpost-format", kRxPostFormat);
    setProperty("rtl812x-rxpost-state",
                (snap->flags & (kRxPostHdrFlagRearmLost |
                                kRxPostHdrFlagNoBaseline |
                                kRxPostHdrFlagTruncated))
                    ? "degraded" : "ok");
}
'''



# Round 15 is intentionally non-VTD only: its exported spans are physical, not
# IOVM addresses. No ordinary allocator may install a receive buffer once the
# allocation domain has been frozen by Prepare.
HPP_INCLUDE_NEW += '#include "RTL812xRxPool.hpp"\n'
HPP_MEMBERS_NEW += '''
    struct R15PoolState;
    R15PoolState *r15Pool;
    static IOReturn r15PoolAction(OSObject *, void *, void *, void *, void *);
    IOReturn r15PoolControl(r15pool::Request *request);
    mbuf_t r15PoolCopy(mbuf_t packet, UInt32 length);
    void r15PoolRearm(UInt32 slot, UInt64 oldAddr, UInt32 status,
                      UInt32 length, UInt32 token, UInt32 reqId, UInt64 *addr);
    void r15PoolPosted(UInt32 slot, UInt64 addr);
    void r15PoolInvalidate();
    void r15PoolFree();
    bool r15PoolObserve(UInt32 kind, UInt32 slot, UInt32 token);
'''
POOL_HPP_API_OLD = '    virtual void free() override;\n'
POOL_HPP_API_NEW = POOL_HPP_API_OLD + '''    virtual IOReturn callPlatformFunction(const OSSymbol *functionName,
        bool waitForFunction, void *param1, void *param2,
        void *param3, void *param4) override;
'''
POOL_RX_OLD = '        newPkt = rxPool->replaceOrCopyPacket(&bufPkt, pktSize, &replaced);'
POOL_RX_NEW = '''        if (r15Pool) {
            /* Pool mbufs NEVER escape to the stack. Delivery owns a copy. */
            replaced = false;
            newPkt = r15PoolCopy(bufPkt, (UInt32)pktSize);
        } else {
            newPkt = rxPool->replaceOrCopyPacket(&bufPkt, pktSize, &replaced);
        }'''
# Selection happens before the address store; the witness tPost is stamped
# AFTER the actual DescOwn store, not at the selection/authorization site.
RX_NEW = RX_NEW.replace(
    '        desc->buf.addr = OSSwapHostToLittleInt64(addr);\n'
    '        desc->buf.blen = OSSwapHostToLittleInt64(word1);',
    '''        r15PoolRearm(rxNextDescIndex, obsRxAddr, descStatus1,
                       (UInt32)(descStatus1 & 0x1fff),
                       obsRxToken, obsRxReq, &addr);
        desc->buf.addr = OSSwapHostToLittleInt64(addr);
        wmb();
        desc->buf.blen = OSSwapHostToLittleInt64(word1);
        r15PoolPosted(rxNextDescIndex, addr);''')

POOL_METHODS = r'''
#pragma mark --- round 15 finite owned receive allocation domain ---

struct RTL8125::R15PoolState {
    r15pool::Snapshot snap;
    mbuf_t mbufs[r15pool::kMaxEntries];
    IOBufferMemoryDescriptor *regions[r15pool::kMaxEntries];
    UInt32 slotId[r15pool::kRingCount];
    UInt32 slotWitness[r15pool::kRingCount]; // 0 = none, otherwise index + 1
    UInt32 keepTx[kNumTxDesc]; // atomic: output submit vs interrupt completion
    UInt32 filtered[5];       // atomic, separate from snapshot-copy memory
    UInt32 physicalAttempts;
    UInt32 physicalFailures[4]; // allocation, prepare, attach, span
};

/* Verify the WHOLE device-writable span, not merely the first physical byte.
 * A single mbuf is not a promise of physical contiguity. Walk every physical
 * page transition plus the final byte, and reject rather than guess. */
static bool r15PhysicalSpan(mbuf_t m, UInt64 *base)
{
    if (!m || mbuf_next(m) || !mbuf_datastart(m) ||
        mbuf_maxlen(m) < kRxBufferSize) return false;
    const UInt8 *start = (const UInt8 *)mbuf_datastart(m);
    const UInt64 pa = mbuf_data_to_physical((void *)start);
    if (!pa || pa + kRxBufferSize < pa) return false;
    for (UInt32 off = 0; off < kRxBufferSize; ) {
        if (mbuf_data_to_physical((void *)(start + off)) != pa + off)
            return false;
        UInt32 step = (UInt32)(PAGE_SIZE -
            ((uintptr_t)(start + off) & (PAGE_SIZE - 1)));
        off += step;
    }
    if (mbuf_data_to_physical((void *)(start + kRxBufferSize - 1)) !=
        pa + kRxBufferSize - 1) return false;
    *base = pa;
    return true;
}

/* The public attach API accepts an external buffer plus its free callback.
 * Its SDK prose recommends mbuf_alloccluster; this custom backing is verified
 * against this target's XNU m_clattach implementation, NOT claimed portable to
 * every kernel. The wrapper never escapes/copies its cluster reference. The
 * descriptor stays solely pool-owned; callback deliberately cannot release it.
 * On every rejection/teardown free the wrapper FIRST, then complete/release the
 * descriptor. Never feed this arbitrary VM buffer to mbuf_data_to_physical. */
static void r15ExternalFree(caddr_t, u_int, caddr_t) {}

static void r15ReleaseOwned(mbuf_t m, IOBufferMemoryDescriptor *region)
{
    if (m) mbuf_freem_list(m);
    if (region) {
        region->complete();
        region->release();
    }
}

IOReturn RTL8125::callPlatformFunction(const OSSymbol *functionName,
    bool waitForFunction, void *param1, void *param2, void *param3, void *param4)
{
    if (!functionName || !functionName->isEqualTo(r15pool::kFunctionName))
        return super::callPlatformFunction(functionName, waitForFunction,
                                           param1, param2, param3, param4);
    if (!param1 || param2 || param3 || param4 || !commandGate)
        return kIOReturnBadArgument;
    r15pool::Request *r = (r15pool::Request *)param1;
    if (r->version != r15pool::kVersion || r->bytes != sizeof(*r))
        return kIOReturnBadArgument;
    return commandGate->runAction(r15PoolAction, r);
}

IOReturn RTL8125::r15PoolAction(OSObject *owner, void *arg0,
                              void *, void *, void *)
{
    RTL8125 *self = (RTL8125 *)owner;
    /* Gate excludes workloop interrupt/reset; __POLLING ALSO excludes the
     * independent input polling thread. Never spin/wait on that thread. */
    if (self->useAppleVTD) return kIOReturnUnsupported;
    if (test_and_set_bit(__POLLING, &self->stateFlags)) return kIOReturnBusy;
    IOReturn result = self->r15PoolControl((r15pool::Request *)arg0);
    clear_bit(__POLLING, &self->stateFlags);
    return result;
}

IOReturn RTL8125::r15PoolControl(r15pool::Request *request)
{
    if (request->op < r15pool::kPrepare || request->op > r15pool::kDisarm)
        return kIOReturnBadArgument;
    if (request->op == r15pool::kPrepare && !r15Pool) {
        if (!rxBufArray || !rxDescArray || !rxPool || !netif ||
            !test_bit(__ENABLED, &stateFlags) ||
            !test_bit(__LINK_UP, &stateFlags)) return kIOReturnNotReady;
        R15PoolState *p = (R15PoolState *)IOMallocZero(sizeof(R15PoolState));
        if (!p) return kIOReturnNoMemory;
        p->snap.version = r15pool::kVersion;
        p->snap.bytes = sizeof(p->snap);
        p->snap.generation = rxpostHdr ?
            __atomic_load_n(&rxpostHdr->ringGen, __ATOMIC_RELAXED) : 1u;
        p->snap.epoch = obsEpoch;
        p->snap.mtu = mtu;
        p->snap.bufferSize = kRxBufferSize;
        p->snap.reserved[0] = request->reserved; // immutable scope token
        for (UInt32 i = 0; i < kNumTxDesc; i++) p->keepTx[i] = 1u;
        /* Ring objects are BORROWED until the single commit below. On failure
         * free only spares, never a buffer still installed in the live ring. */
        bool valid = true;
        for (UInt32 i = 0; i < r15pool::kRingCount; i++) {
            UInt64 pa = 0;
            if (!r15PhysicalSpan(rxBufArray[i].mbuf, &pa) ||
                pa != rxBufArray[i].phyAddr ||
                pa != OSSwapLittleToHostInt64(rxDescArray[i].buf.addr)) {
                valid = false; break;
            }
            for (UInt32 j = 0; j < i; j++) {
                UInt64 other = p->snap.entries[j].addr;
                if (pa < other + kRxBufferSize && other < pa + kRxBufferSize)
                    valid = false;
            }
            if (!valid) break;
            p->mbufs[i] = rxBufArray[i].mbuf;
            p->slotId[i] = i;
            p->snap.entries[i].addr = pa;
            p->snap.entries[i].capacity = kRxBufferSize;
            p->snap.entries[i].id = i;
            p->snap.entries[i].kind = r15pool::kEntryRing;
        }
        /* Bounded high-first selection, with NO exclusion of low addresses.
         * At most kSpareCount candidates plus one being considered are held;
         * the matching pool ABI budgets 2048 mbuf + 1024 IOBuffer attempts.
         * Nothing allocated here is posted before mapping authorization.
         * Descriptor allocation may block: this is gated thread-context Prepare
         * before DTE switching, never interrupt level or an OS simple lock. */
        if (valid) for (UInt32 attempt = 0; attempt < r15pool::kMaxAttempts +
                       r15pool::kExtraIOBufferAttempts; attempt++) {
            mbuf_t m = NULL;
            IOBufferMemoryDescriptor *region = NULL;
            UInt64 pa = 0;
            p->snap.allocationAttempts++;
            if (attempt < r15pool::kMaxAttempts) {
                unsigned int chunks = 1;
                if (mbuf_allocpacket(MBUF_DONTWAIT, kRxBufferSize, &chunks, &m))
                    continue;
                if (!r15PhysicalSpan(m, &pa)) {
                    mbuf_freem_list(m); continue;
                }
            } else {
                p->physicalAttempts++;
                region = IOBufferMemoryDescriptor::inTaskWithOptions(kernel_task,
                    kIODirectionInOut | kIOMemoryMapperNone,
                    kRxBufferSize, PAGE_SIZE);
                if (!region) { p->physicalFailures[0]++; continue; }
                if (region->prepare() != kIOReturnSuccess) {
                    p->physicalFailures[1]++; region->release(); continue;
                }
                IOByteCount span = 0;
                void *bytes = region->getBytesNoCopy();
                pa = region->getPhysicalSegment(0, &span, kIOMemoryMapperNone);
                if (!bytes || region->getLength() < kRxBufferSize || !pa ||
                    pa + kRxBufferSize < pa || span < kRxBufferSize) {
                    p->physicalFailures[3]++;
                    r15ReleaseOwned(NULL, region); continue;
                }
                if (mbuf_gethdr(MBUF_DONTWAIT, MBUF_TYPE_DATA, &m) ||
                    mbuf_attachcluster(MBUF_DONTWAIT, MBUF_TYPE_DATA, &m,
                        (caddr_t)bytes, r15ExternalFree, kRxBufferSize, NULL)) {
                    p->physicalFailures[2]++;
                    r15ReleaseOwned(m, region); continue;
                }
                if (!m || mbuf_next(m) || mbuf_datastart(m) != bytes ||
                    mbuf_maxlen(m) < kRxBufferSize) {
                    p->physicalFailures[3]++;
                    r15ReleaseOwned(m, region); continue;
                }
            }
            bool overlaps = false;
            UInt32 have = r15pool::kRingCount + p->snap.spareCount;
            for (UInt32 j = 0; j < have; j++) {
                UInt64 other = p->snap.entries[j].addr;
                if (pa < other + kRxBufferSize && other < pa + kRxBufferSize)
                    overlaps = true;
            }
            if (overlaps) { r15ReleaseOwned(m, region); continue; }
            UInt32 keep = have;
            if (p->snap.spareCount == r15pool::kSpareCount) {
                keep = r15pool::kRingCount;
                for (UInt32 j = keep + 1; j < r15pool::kMaxEntries; j++)
                    if (p->snap.entries[j].addr < p->snap.entries[keep].addr)
                        keep = j;
                if (pa <= p->snap.entries[keep].addr) {
                    r15ReleaseOwned(m, region); continue;
                }
                r15ReleaseOwned(p->mbufs[keep], p->regions[keep]);
            } else p->snap.spareCount++;
            mbuf_setdata(m, mbuf_datastart(m), 0);
            p->mbufs[keep] = m;
            p->regions[keep] = region;
            p->snap.entries[keep].reserved = region ?
                r15pool::kSourceIOBuffer : r15pool::kSourceMbuf;
            p->snap.entries[keep].addr = pa;
            p->snap.entries[keep].capacity = kRxBufferSize;
            p->snap.entries[keep].kind = r15pool::kEntrySpare;
        }
        if (!valid || p->snap.spareCount != r15pool::kSpareCount) {
            for (UInt32 i = r15pool::kRingCount; i < r15pool::kMaxEntries; i++)
                r15ReleaseOwned(p->mbufs[i], p->regions[i]);
            IOFree(p, sizeof(*p));
            return valid ? kIOReturnNoMemory : kIOReturnNotAligned;
        }
        /* Highest actual physical address is the first replacement. */
        for (UInt32 i = r15pool::kRingCount; i < r15pool::kMaxEntries; i++) {
            UInt32 high = i;
            for (UInt32 j = i + 1; j < r15pool::kMaxEntries; j++)
                if (p->snap.entries[j].addr > p->snap.entries[high].addr) high = j;
            r15pool::Entry e = p->snap.entries[i];
            p->snap.entries[i] = p->snap.entries[high];
            p->snap.entries[high] = e;
            mbuf_t m = p->mbufs[i]; p->mbufs[i] = p->mbufs[high];
            p->mbufs[high] = m;
            IOBufferMemoryDescriptor *region = p->regions[i];
            p->regions[i] = p->regions[high];
            p->regions[high] = region;
            p->snap.entries[i].id = i;
            if (p->snap.entries[i].addr >= 0x400000000ULL)
                p->snap.highSpareCount++;
        }
        p->snap.entryCount = r15pool::kMaxEntries;
        p->snap.tPrepared = mach_absolute_time();
        p->snap.poolId = p->snap.tPrepared ? p->snap.tPrepared : 1;
        p->snap.state = r15pool::kPrepared;
        /* TX output runs outside the command gate/RX guard. Publish the
         * fully initialized immutable token + TX slot table with release. */
        __atomic_store_n(&r15Pool, p, __ATOMIC_RELEASE);
    }
    if (!r15Pool) return kIOReturnNotReady;
    R15PoolState *p = r15Pool;
    if (request->op != r15pool::kPrepare &&
        (request->poolId != p->snap.poolId ||
         request->expectedGeneration != p->snap.generation))
        return kIOReturnBadArgument;
    if (request->op == r15pool::kAuthorize) {
        UInt64 now = mach_absolute_time(), maxWindow = 0;
        nanoseconds_to_absolutetime(10000000000ULL, &maxWindow);
        if (p->snap.state != r15pool::kPrepared || p->snap.flags ||
            !request->mapCompletedAt || request->mapCompletedAt < p->snap.tPrepared ||
            request->mapCompletedAt > now || request->deadline <= now ||
            request->deadline - now > maxWindow ||
            !request->replaceLimit || request->replaceLimit > r15pool::kSpareCount)
            return kIOReturnBadArgument;
        p->snap.mapCompletedAt = request->mapCompletedAt;
        p->snap.deadline = request->deadline;
        p->snap.replaceLimit = request->replaceLimit;
        p->snap.tAuthorized = now;
        p->snap.rxCompletions = 0;
        __atomic_store_n(&p->snap.state, (UInt32)r15pool::kAuthorized,
                         __ATOMIC_RELEASE);
    } else if (request->op == r15pool::kDisarm) {
        __atomic_store_n(&p->snap.state, (UInt32)r15pool::kDisarmed,
                         __ATOMIC_RELEASE);
    }
    setProperty("rtl812x-r15-physical-allocation-attempts", p->physicalAttempts, 32);
    setProperty("rtl812x-r15-physical-allocation-failures", p->physicalFailures[0], 32);
    setProperty("rtl812x-r15-physical-prepare-failures", p->physicalFailures[1], 32);
    setProperty("rtl812x-r15-physical-attach-failures", p->physicalFailures[2], 32);
    setProperty("rtl812x-r15-physical-span-failures", p->physicalFailures[3], 32);
    UInt32 totalFiltered = 0;
    for (UInt32 i = 1; i < 5; i++)
        totalFiltered += __atomic_load_n(&p->filtered[i], __ATOMIC_RELAXED);
    p->snap.reserved[1] = totalFiltered;
    if (p->snap.reserved[0]) {
        setProperty("rtl812x-r15-obs-scope",
            "declared-business-only; all-rxpost-and-pool-witnesses-retained");
        setProperty("rtl812x-r15-obs-business-token", p->snap.reserved[0], 32);
        setProperty("rtl812x-r15-obs-filtered-txsubmit",
            __atomic_load_n(&p->filtered[kObsKindTxSubmit], __ATOMIC_RELAXED), 32);
        setProperty("rtl812x-r15-obs-filtered-txdone",
            __atomic_load_n(&p->filtered[kObsKindTxDone], __ATOMIC_RELAXED), 32);
        setProperty("rtl812x-r15-obs-filtered-rxdone",
            __atomic_load_n(&p->filtered[kObsKindRxDone], __ATOMIC_RELAXED), 32);
        setProperty("rtl812x-r15-obs-filtered-doorbell",
            __atomic_load_n(&p->filtered[kObsKindTxDoorbell], __ATOMIC_RELAXED), 32);
    } else setProperty("rtl812x-r15-obs-scope", "all-observation-rows");
    bcopy(&p->snap, &request->out, sizeof(request->out));
    return kIOReturnSuccess;
}

bool RTL8125::r15PoolObserve(UInt32 kind, UInt32 slot, UInt32 token)
{
    R15PoolState *p = __atomic_load_n(&r15Pool, __ATOMIC_ACQUIRE);
    if (!p || !p->snap.reserved[0]) return true;
    bool keep = true;
    if (kind == kObsKindTxSubmit) {
        keep = token == p->snap.reserved[0];
        if (slot < kNumTxDesc)
            __atomic_store_n(&p->keepTx[slot], keep ? 1u : 0u, __ATOMIC_RELEASE);
    } else if (kind == kObsKindTxDone) {
        keep = slot < kNumTxDesc &&
            __atomic_load_n(&p->keepTx[slot], __ATOMIC_ACQUIRE) != 0;
    } else if (kind == kObsKindRxDone || kind == kObsKindTxDoorbell) {
        keep = token == p->snap.reserved[0];
    }
    if (!keep && kind < 5)
        __atomic_fetch_add(&p->filtered[kind], 1u, __ATOMIC_RELAXED);
    return keep;
}

mbuf_t RTL8125::r15PoolCopy(mbuf_t packet, UInt32 length)
{
    if (!r15Pool || !length || length > kRxBufferSize) return NULL;
    mbuf_t copy = rxPool->getPacket(length, MBUF_DONTWAIT);
    if (copy && mbuf_trailingspace(copy) >= length) {
        mbuf_copy_pkthdr(copy, packet);
        mbuf_pkthdr_setheader(copy, NULL);
        bcopy(mbuf_data(packet), mbuf_data(copy), length);
        return copy;
    }
    if (copy) mbuf_freem_list(copy);
    r15Pool->snap.copyFailures++;
    r15Pool->snap.flags |= r15pool::kFlagCopyFailed;
    return NULL;
}

void RTL8125::r15PoolRearm(UInt32 slot, UInt64 oldAddr, UInt32 status,
    UInt32 length, UInt32 token, UInt32 reqId, UInt64 *addr)
{
    if (!r15Pool || slot >= r15pool::kRingCount) return;
    R15PoolState *p = r15Pool;
    UInt64 now = mach_absolute_time();
    p->snap.rxCompletions++;
    UInt32 id = p->slotId[slot];
    if (id >= p->snap.entryCount || oldAddr != p->snap.entries[id].addr ||
        rxBufArray[slot].mbuf != p->mbufs[id] ||
        oldAddr != OSSwapLittleToHostInt64(rxDescArray[slot].buf.addr)) {
        p->snap.flags |= r15pool::kFlagAddressMismatch;
        __atomic_store_n(&p->snap.state, (UInt32)r15pool::kDisarmed,
                         __ATOMIC_RELEASE);
        /* Hard domain interlock: even a detected external association change
         * must not re-post an unexported address at nextDesc. Restore a known
         * retained object, never free/dereference the unexpected foreign one. */
        UInt32 canonical = id < p->snap.entryCount ? id : slot;
        p->slotId[slot] = canonical;
        rxBufArray[slot].mbuf = p->mbufs[canonical];
        rxBufArray[slot].phyAddr = p->snap.entries[canonical].addr;
        *addr = p->snap.entries[canonical].addr;
        return;
    }
    UInt32 wi = p->slotWitness[slot];
    if (wi && wi <= p->snap.replacements) {
        r15pool::Witness *w = &p->snap.witnesses[wi - 1];
        if (!w->tDone && w->tPost && w->newAddr == oldAddr) {
            w->tDone = now;
            w->token = token; w->reqId = reqId;
            w->doneLength = length; w->doneStatus = status;
            w->flags = (status & RxRES) ? r15pool::kWitnessError :
                                         r15pool::kWitnessCompleted;
            p->snap.completions++;
        }
    }
    if (__atomic_load_n(&p->snap.state, __ATOMIC_ACQUIRE) !=
        r15pool::kAuthorized) return;
    if (now > p->snap.deadline) {
        p->snap.flags |= r15pool::kFlagExpired;
        __atomic_store_n(&p->snap.state, (UInt32)r15pool::kDisarmed,
                         __ATOMIC_RELEASE);
        return;
    }
    if ((status & RxRES) || p->snap.replacements >= p->snap.replaceLimit)
        return;
    UInt32 n = p->snap.replacements;
    UInt32 next = r15pool::kRingCount + n;
    r15pool::Witness *w = &p->snap.witnesses[n];
    w->oldAddr = oldAddr; w->newAddr = p->snap.entries[next].addr;
    w->slot = slot; w->capacity = kRxBufferSize; w->entryId = next;
    p->slotId[slot] = next;
    p->slotWitness[slot] = n + 1;
    p->snap.replacements = n + 1;
    /* Retired original stays in mbufs[] and is NEVER freed or delivered. */
    rxBufArray[slot].mbuf = p->mbufs[next];
    rxBufArray[slot].phyAddr = w->newAddr;
    *addr = w->newAddr;
}

void RTL8125::r15PoolPosted(UInt32 slot, UInt64 addr)
{
    if (!r15Pool || slot >= r15pool::kRingCount) return;
    UInt32 wi = r15Pool->slotWitness[slot];
    if (wi && wi <= r15Pool->snap.replacements) {
        r15pool::Witness *w = &r15Pool->snap.witnesses[wi - 1];
        if (!w->tPost && w->newAddr == addr) w->tPost = mach_absolute_time();
    }
}

void RTL8125::r15PoolInvalidate()
{
    if (!r15Pool) return;
    __atomic_store_n(&r15Pool->snap.state, (UInt32)r15pool::kDisarmed,
                     __ATOMIC_RELEASE);
    __atomic_fetch_add(&r15Pool->snap.generation, 1u, __ATOMIC_RELAXED);
    __atomic_fetch_or(&r15Pool->snap.flags, (UInt32)r15pool::kFlagRingReset,
                      __ATOMIC_RELAXED);
}

void RTL8125::r15PoolFree()
{
    if (!r15Pool) return;
    /* Called from freeRxResources AFTER interface detach/RX shutdown, never
     * from Disarm. Ring entries are aliases, so null them before freeing the
     * single owning array to prevent the upstream cleanup freeing them twice. */
    if (rxBufArray) for (UInt32 i = 0; i < r15pool::kRingCount; i++) {
        rxBufArray[i].mbuf = NULL;
        rxBufArray[i].phyAddr = 0;
    }
    for (UInt32 i = 0; i < r15Pool->snap.entryCount; i++)
        r15ReleaseOwned(r15Pool->mbufs[i], r15Pool->regions[i]);
    IOFree(r15Pool, sizeof(*r15Pool));
    r15Pool = NULL;
}
'''


def read(path):
    with open(path, "r", encoding="utf-8", errors="surrogateescape") as f:
        return f.read()


def write(path, text):
    with open(path, "w", encoding="utf-8", errors="surrogateescape",
              newline="\n") as f:
        f.write(text)


# Round 16 / 17: explicit real-TX mapping, independently testable templates.
# Round16 staged a page-aligned copy; round17 maps the packet's own physical
# segments and recycles every request's mbuf. Both templates are kept so the
# archived round-16 evidence stays reproducible from its own generator input.
import runpy
TX16 = runpy.run_path(os.path.join(HERE, 'r16', 'driver-template.py'))
TX17 = runpy.run_path(os.path.join(HERE, 'r17', 'driver-template.py'))
TX18 = runpy.run_path(os.path.join(HERE, 'r18', 'driver-template.py'))
TX19 = runpy.run_path(os.path.join(HERE, 'r19', 'driver-template.py'))
# Round 20 keeps the same standard path and adds: per-object identity coverage
# for ordinary TX (kCover), the blocked-ring record, the paired complete() on
# every pre-publish multi-range exit, and kSegments=8 in the std witness.
TX20 = runpy.run_path(os.path.join(HERE, 'r20', 'driver-template.py'))
# Round21 keeps round 20's generator untouched and derives its own: the window
# gate, the forced exit sample and the whitelisted control ops are round-21
# behaviour, and leaving r20 selectable is what lets the archived round-20
# evidence stay reproducible byte-for-byte.
TX21 = runpy.run_path(os.path.join(HERE, 'r21', 'driver-template.py'))
# round -> (module, [headers written into the driver tree, in include order])
TXR = {'16': (TX16, ['RTL812xTxMap.hpp']),
       '17': (TX17, ['RTL812xTxMapNative.hpp']),
       '18': (TX18, ['RTL812xTxMapNative.hpp', 'RTL812xTxMapStd.hpp']),
       '19': (TX19, ['RTL812xTxMapNative.hpp', 'RTL812xTxMapStd.hpp']),
       '20': (TX20, ['RTL812xTxMapNative.hpp', 'RTL812xTxMapStd.hpp']),
       '21': (TX21, ['RTL812xTxMapNative.hpp', 'RTL812xTxMapStd.hpp'])}
TX_SELECT = '16'
TX, TXMAP_NAMES = TXR[TX_SELECT]
TXMAP_NAME = TXMAP_NAMES[0]
TXMAP_SRC = os.path.join(HERE, 'lucy-obs', TXMAP_NAME)
RX_SELECT = '15'
RX = None
RXMAP_NAMES = []
_HPP_INCLUDE_BASE = HPP_INCLUDE_NEW
_HPP_MEMBERS_BASE = HPP_MEMBERS_NEW
_POOL_METHODS_BASE = POOL_METHODS
_RX_BIZ_BASE = RX_BIZ_NEW
_RX_REARM_BASE = RX_NEW
_RX_DECL_BASE = RX_DECL_NEW
_RX_CAPTURE_BASE = RX_CAPTURE_NEW
_POOL_RX_BASE = POOL_RX_NEW
HPP_INCLUDE_NEW += ''.join('#include "%s"\n' % n for n in TXMAP_NAMES)
HPP_MEMBERS_NEW += TX['MEMBERS']


def select_tx(round_no):
    """Pick the TX module at patch time (default 16: historical behaviour)."""
    global TX_SELECT, TX, TXMAP_NAME, TXMAP_NAMES, TXMAP_SRC
    global HPP_INCLUDE_NEW, HPP_MEMBERS_NEW
    if round_no not in TXR:
        raise SystemExit('unsupported TX module round: %r' % (round_no,))
    TX_SELECT = round_no
    TX, TXMAP_NAMES = TXR[round_no]
    TXMAP_NAME = TXMAP_NAMES[0]
    TXMAP_SRC = os.path.join(HERE, 'lucy-obs', TXMAP_NAME)
    HPP_INCLUDE_NEW = _HPP_INCLUDE_BASE + ''.join(
        '#include "%s"\n' % n for n in TXMAP_NAMES + RXMAP_NAMES)
    HPP_MEMBERS_NEW = _HPP_MEMBERS_BASE + TX['MEMBERS'] + (RX['MEMBERS'] if RX else '')
    return TX


def select_rx(round_no):
    """Opt in to standard-mapped RX without rewriting historical TX."""
    global RX_SELECT, RX, RXMAP_NAMES, POOL_METHODS, RX_BIZ_NEW
    global RX_NEW, RX_DECL_NEW, RX_CAPTURE_NEW, POOL_RX_NEW
    if round_no not in ('15', '27', '28', '29', '30', '31', '32', '33', '34'):
        raise SystemExit('unsupported RX module round: %r' % (round_no,))
    RX_SELECT = round_no
    RX = runpy.run_path(os.path.join(HERE, 'r34' if round_no == '34' else 'r27',
                                   'driver-template.py')) if round_no != '15' else None
    RXMAP_NAMES = RX['HEADERS'] if RX else []
    POOL_METHODS = RX['pool_methods'](_POOL_METHODS_BASE) if RX else _POOL_METHODS_BASE
    if RX:
        # Current cyclic RX accepts deadline=0 until explicit Disarm; a finite
        # request still has the 120-second bound. Historical RX15 stays finite.
        POOL_METHODS = POOL_METHODS.replace('10000000000ULL, &maxWindow',
                                            '120000000000ULL, &maxWindow')
        POOL_METHODS = POOL_METHODS.replace(
            'request->deadline <= now ||\n'
            '            request->deadline - now > maxWindow ||',
            '(request->deadline && (request->deadline <= now ||\n'
            '             request->deadline - now > maxWindow)) ||')
    RX_BIZ_NEW = RX['rx_business'](_RX_BIZ_BASE) if RX else _RX_BIZ_BASE
    RX_NEW = RX['rx_rearm'](_RX_REARM_BASE) if RX else _RX_REARM_BASE
    RX_DECL_NEW = RX['rx_decl'](_RX_DECL_BASE) if RX else _RX_DECL_BASE
    RX_CAPTURE_NEW = RX['rx_capture'](_RX_CAPTURE_BASE) if RX else _RX_CAPTURE_BASE
    POOL_RX_NEW = RX['pool_receive'](_POOL_RX_BASE) if RX and 'pool_receive' in RX else _POOL_RX_BASE
    select_tx(TX_SELECT)
    return RX


# The round-16 template predates this hook list and is kept byte-identical, so
# its call-site markers live here instead of in that file.
TX_HOOKS = {
    '16': ('if (!r16TxMap(m, txSegments, numSegs)) continue;',
           'r16TxComplete(txDirtyDescIndex);', 'r16TxPosted(m);',
           'r16TxStop();', 'r16Tx = NULL;',
           'functionName->isEqualTo(r16tx::kFunctionName)',
           'p->packet == m) ? NULL : m;'),
}


def tx_hooks():
    return TX.get('HOOKS') or TX_HOOKS[TX_SELECT]


def sync_headers(drv):
    """Copy the two headers into the driver directory if they differ.

    Returns the number of files actually rewritten. The build compiles the
    copies, so this is what keeps "the header this repository records" and "the
    header the driver was built from" the same file.
    """
    changed = 0
    pairs = [(HDR_SRC, "RTL812xObsLog.hpp"),
             (WRITE_SRC, "RTL812xObsWrite.hpp"),
             (RXPOST_SRC, "RTL812xRxPost.hpp"),
             (POOL_SRC, "RTL812xRxPool.hpp")]
    pairs += [(os.path.join(HERE, 'lucy-obs', name), name)
              for name in TXMAP_NAMES + RXMAP_NAMES]
    for src, name in pairs:
        want = read(src)
        dst = os.path.join(drv, name)
        have = read(dst) if os.path.isfile(dst) else None
        if have != want:
            write(dst, want)
            changed += 1
    return changed


def body_is_current(cpp_text):
    """Does the ALREADY-PATCHED cpp contain the CURRENT template's method body?

    WHY THIS EXISTS -- and why it is not paranoia
    ---------------------------------------------
    `OBS_METHODS` is a template: `obsWrite()` and `obsPublish()` are written
    into the driver by TEXT SUBSTITUTION at patch time. So editing the template
    changes nothing in a tree that was already patched. The patch reports
    "already applied" and the driver keeps compiling the OLD method bodies.

    That is exactly what happened in round 13: the fix to the wrapped counter
    added `&obsWrapped` to the `writeRecord(...)` call in the template, the
    patch said "already applied", and the built driver still called
    `writeRecord(..., &obsDropped)`. The header was new, the method body was
    old, and the two disagreed about how many arguments `writeRecord` takes --
    which the C++ compiler would catch, but only if someone rebuilt.

    The check compares the template's `obsPublish()` and `obsWrite()` bodies
    against the ones in the tree. If they differ, the tree is STALE and the
    patch refuses rather than pretending to have applied a change it did not
    make. Re-extracting the upstream source is the fix; rewriting a 600 KB cpp
    in place is not something this script should do silently.
    """
    norm_pool = lambda s: re.sub(r'\s+', ' ', s).strip()
    for hook in tx_hooks():
        if hook not in cpp_text:
            return False, 'round%s TX hook %s' % (TX_SELECT, hook)
    pool_struct = POOL_METHODS[POOL_METHODS.index('struct RTL8125::R15PoolState {'):]
    pool_struct = pool_struct[:pool_struct.index('\n};') + 3]
    if norm_pool(pool_struct) not in norm_pool(cpp_text):
        return False, 'round15 pool state'
    # Round 18 keeps the round-17 identifiers on purpose (the call sites and the
    # patch anchors are shared), so the names are declarative rather than derived.
    state_mark = 'struct RTL8125::%s {' % TX.get('STATE_NAME',
                                                 'R%sTxState' % TX_SELECT)
    module_mark = 'IOReturn RTL8125::%s' % TX.get('CONFIG_NAME',
                                                  'r%sTxConfigure' % TX_SELECT)
    state_start = TX['METHODS'].index(state_mark)
    state_end = TX['METHODS'].index('\n};', state_start) + 3
    struct_start = TX['METHODS'].find('struct RTL8125::R17Gen {')
    if struct_start < 0 or struct_start > state_start:
        struct_start = state_start
    # The generated prefix includes the generation type and the Round32
    # admission guard; both must match along with the state that uses them.
    tx_struct = TX['METHODS'][struct_start:state_end]
    for block, label in ((tx_struct, 'round%s TX state' % TX_SELECT),
                         (TX['METHODS'].split(module_mark)[1],
                          'round%s TX module' % TX_SELECT),
                         (POOL_RX_NEW, 'round15 copy hook'),
                         (RX_NEW, 'round15 rearm hook'),
                         (RX_BIZ_NEW, 'RX business observer'),
                         (RX_DECL_NEW, 'RX locals'),
                         (RX_CAPTURE_NEW, 'RX capture reset')):
        if norm_pool(block) not in norm_pool(cpp_text):
            return False, label
    for name in ('obsWrite', 'obsPublish', 'rxpostInit', 'rxpostFree',
                 'rxpostBumpGen', 'rxpostCaptureBaseline',
                 'rxpostRecordRearm', 'rxpostPublish', 'r15PoolControl',
                 'r15PoolCopy', 'r15PoolRearm', 'r15PoolPosted',
                 'r15PoolInvalidate', 'r15PoolFree', 'r15PoolAction',
                 'r15PoolObserve') + (('r27RxAction', 'r27RxControl',
                 'r27RxRearm', 'r27RxPosted', 'r27RxActive', 'r27RxParse') if RX else ()) + (('r34RxBinding', 'r34RxMapSlot',
                 'r34RxUnmapSlot', 'r34RxComplete', 'r34RxRearm', 'r34RxPosted',
                 'r34RxControl', 'r34RxAction', 'r34RxFree', 'r34RxParse',
                 'r34RxCanReplace', 'r34RxCopy', 'r34RxObserve',
                 'r34RxInvalidate', 'r34RxPrepareSlot', 'r34RxFinishMapSlot',
                 'r34RxRecordDone', 'r36RxBatchCall', 'r36RxBeginBatch',
                 'r36RxPublish') if RX_SELECT == '34' else ()):
        m = re.search(r'^(?:void|bool|IOReturn|mbuf_t) RTL8125::%s\(.*?\)\s*(?:const\s*)?\{' % name,
                      OBS_METHODS + RXPOST_METHODS + POOL_METHODS, re.M | re.S)
        if not m:
            return True, None          # cannot judge -> do not block
        start = m.end() - 1
        depth = 0
        i = start
        tmpl = OBS_METHODS + RXPOST_METHODS + POOL_METHODS
        while i < len(tmpl):
            if tmpl[i] == '{':
                depth += 1
            elif tmpl[i] == '}':
                depth -= 1
                if depth == 0:
                    break
            i += 1
        want = tmpl[start:i + 1]

        m2 = re.search(r'^(?:void|bool|IOReturn|mbuf_t) RTL8125::%s\(.*?\)\s*(?:const\s*)?\{' % name,
                       cpp_text, re.M | re.S)
        if not m2:
            return False, name
        start2 = m2.end() - 1
        depth = 0
        j = start2
        while j < len(cpp_text):
            if cpp_text[j] == '{':
                depth += 1
            elif cpp_text[j] == '}':
                depth -= 1
                if depth == 0:
                    break
            j += 1
        have = cpp_text[start2:j + 1]

        # Compare on a whitespace-normalised basis: the substitution inserts
        # the template verbatim, so a difference is a REAL difference in code,
        # not in formatting.
        norm = lambda s: re.sub(r'\s+', ' ', s).strip()
        if norm(have) != norm(want):
            return False, name
    return True, None


def replace_once(text, old, new, what):
    n = text.count(old)
    if n != 1:
        raise SystemExit(
            "refused: the anchor for %s occurs %d time(s), expected exactly 1.\n"
            "The upstream source is not the expected revision." % (what, n))
    return text.replace(old, new, 1)


def main():
    argv = sys.argv[1:]
    positional, tx, rx = [], None, None
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == '--tx' and i + 1 < len(argv):
            tx = argv[i + 1]; i += 2; continue
        if a.startswith('--tx='):
            tx = a.split('=', 1)[1]; i += 1; continue
        if a.startswith('--tx'):
            tx = a[4:]; i += 1; continue
        if a == '--rx' and i + 1 < len(argv):
            rx = argv[i + 1]; i += 2; continue
        if a.startswith('--rx='):
            rx = a.split('=', 1)[1]; i += 1; continue
        if a.startswith('--rx'):
            rx = a[4:]; i += 1; continue
        positional.append(a); i += 1
    if len(positional) != 1 or (tx is not None and tx not in TXR) or (rx is not None and rx not in ('15', '27', '28', '29', '30', '31', '32', '33', '34')):
        print("usage: apply-lucy-obs2.py <RTL812xLucy-commit-dir> [--tx 16..21] [--rx 15|27|28|29|30|31|32|33|34]")
        return 2
    if tx is not None:
        select_tx(tx)
    if rx is not None:
        select_rx(rx)
    if RX_SELECT in ('27', '28', '29', '30', '31', '32', '33', '34') and TX_SELECT != '21':
        print("refused: cyclic RX requires the current --tx 21 module")
        return 2
    root = positional[0]
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
    #
    # ROUND 13: "already applied" MUST NOT MEAN "leave the headers alone".
    #
    # The two headers are COPIED into the driver directory and the build
    # compiles the COPIES. Round 12's early return skipped the copy, so after a
    # header changed in tools/lucy-obs/ a re-run reported "already applied" and
    # left the driver compiling the OLD header. That is a silent divergence
    # between the file the manifest hashes and the file the build uses, and
    # tools/r13/deps.sh now fails on it.
    #
    # So an already-applied tree still gets its header copies refreshed, and the
    # exit status says whether anything changed.
    if MARK_CPP in cpp_text or MARK_HPP in hpp_text:
        if MARK_CPP in cpp_text and MARK_HPP in hpp_text:
            # ROUND 14: a tree patched by round 13 has the observation log but
            # NOT the RX post tables. Reporting "already applied" there would
            # ship a driver with none of this round's code and no error.
            if MARK_POOL not in cpp_text:
                print("REFUSED: this tree lacks the round-15 finite RX pool. "
                      "Re-extract pristine upstream and reapply.")
                return 1
            if MARK_RXPOST not in cpp_text:
                print("REFUSED: this tree has the round-10 observation log but "
                      "NOT the round-14 RX post tables.")
                print()
                print("  The RX post tables are written into RTL812xLucy.cpp by")
                print("  TEXT SUBSTITUTION at patch time, so a tree patched by")
                print("  an older template cannot be upgraded in place -- the")
                print("  new method bodies have nowhere to go and the call sites")
                print("  they need are not present.")
                print()
                print("  Re-extract the upstream source and run this script "
                      "again:")
                print()
                print("      rm -rf %s" % root)
                print("      # re-extract RTL812xLucy-<commit> from the tarball")
                print("      python3 tools/apply-lucy-obs2.py <dir>")
                return 1
            fresh, stale = body_is_current(cpp_text)
            if not fresh:
                print("REFUSED: the tree is patched but its %s() body is STALE."
                      % stale)
                print()
                print("  `OBS_METHODS` is written into the driver by text")
                print("  substitution, so editing the template does NOT change")
                print("  a tree that was already patched. This tree was patched")
                print("  from an OLDER template, and the method bodies in it are")
                print("  not the ones this script would write now.")
                print()
                print("  The headers have been refreshed, but the cpp cannot be")
                print("  safely rewritten in place. Re-extract the upstream")
                print("  source and run this script again:")
                print()
                print("      rm -rf %s" % root)
                print("      # re-extract RTL812xLucy-<commit> from the tarball")
                print("      python3 tools/apply-lucy-obs2.py <dir>")
                return 1
            changed = sync_headers(drv)
            if changed:
                print("already applied (the observation log is present); "
                      "refreshed %d header copy/copies" % changed)
            else:
                print("already applied (the observation log is present)")
            return 0
        print("refused: the tree is HALF patched "
              "(cpp has the log: %s, hpp has it: %s). Re-extract the upstream "
              "source before applying." % (MARK_CPP in cpp_text,
                                           MARK_HPP in hpp_text))
        return 1

    # 1. the headers
    hdr_dst = os.path.join(drv, "RTL812xObsLog.hpp")
    write(hdr_dst, read(HDR_SRC))
    print("wrote  %s" % hdr_dst)
    write_dst = os.path.join(drv, "RTL812xObsWrite.hpp")
    write(write_dst, read(WRITE_SRC))
    print("wrote  %s" % write_dst)
    rxpost_dst = os.path.join(drv, "RTL812xRxPost.hpp")
    write(rxpost_dst, read(RXPOST_SRC))
    print("wrote  %s" % rxpost_dst)
    pool_dst = os.path.join(drv, "RTL812xRxPool.hpp")
    write(pool_dst, read(POOL_SRC))
    print("wrote  %s" % pool_dst)
    for name in TXMAP_NAMES + RXMAP_NAMES:
        src = os.path.join(HERE, 'lucy-obs', name)
        write(os.path.join(drv, name), read(src))
        print("wrote  %s" % os.path.join(drv, name))

    # 2. the class
    hpp_text = replace_once(hpp_text, HPP_INCLUDE_OLD, HPP_INCLUDE_NEW,
                            "the include block")
    hpp_text = replace_once(hpp_text, HPP_MEMBERS_OLD, HPP_MEMBERS_NEW,
                            "the flag members")
    hpp_text = replace_once(hpp_text, HPP_FORCE_MEMBER_OLD,
                            HPP_FORCE_MEMBER_NEW, "the force-publish member")
    hpp_text = replace_once(hpp_text, POOL_HPP_API_OLD, POOL_HPP_API_NEW,
                            "round15 platform function declaration")
    write(hpp, hpp_text)
    print("patched %s" % hpp)

    # 3-8. the implementation
    cpp_text = replace_once(cpp_text, '        rxPool = NULL;\n',
                            '        rxPool = NULL;\n        r15Pool = NULL;\n',
                            "round15 pool initialization")
    cpp_text = replace_once(cpp_text, POOL_RX_OLD, POOL_RX_NEW,
                            "round15 owned RX copy delivery")
    cpp_text = replace_once(cpp_text, START_OLD, START_NEW, "start()")
    cpp_text = replace_once(cpp_text, STOP_OLD, STOP_NEW, "stop()")
    cpp_text = replace_once(cpp_text, TIMER_OLD, TIMER_NEW, "the watchdog tick")
    cpp_text = replace_once(cpp_text, OUTPUT_DECL_OLD, OUTPUT_DECL_NEW,
                            "outputStart() locals")
    cpp_text = replace_once(cpp_text, OUTPUT_OLD, OUTPUT_NEW, "outputStart()")
    cpp_text = replace_once(cpp_text, OUTPUT_FILL_OLD, OUTPUT_FILL_NEW,
                            "outputStart() descriptor fill")
    cpp_text = replace_once(cpp_text, OUTPUT_DOORBELL_OLD, OUTPUT_DOORBELL_NEW,
                            "outputStart() doorbell")
    cpp_text = replace_once(cpp_text, TXDONE_OLD, TXDONE_NEW, "txInterrupt()")
    cpp_text = replace_once(cpp_text, RX_DECL_OLD, RX_DECL_NEW,
                            "rxInterrupt() locals")
    cpp_text = replace_once(cpp_text, RX_CAPTURE_OLD, RX_CAPTURE_NEW,
                            "rxInterrupt() address capture")
    cpp_text = replace_once(cpp_text, RX_BIZ_OLD, RX_BIZ_NEW,
                            "rxInterrupt() business capture")
    cpp_text = replace_once(cpp_text, RX_OLD, RX_NEW, "rxInterrupt()")

    # Round 14: the ring-generation bumps and the VTD rearm record.
    setup = os.path.join(drv, "RTL812xLucySetup.cpp")
    vtd = os.path.join(drv, "RTL812xLucyVTD.cpp")
    for p in (setup, vtd):
        if not os.path.isfile(p):
            print("refused: missing %s" % p)
            return 2
    setup_text = read(setup)
    setup_text = replace_once(setup_text, SETUP_GEN_OLD, SETUP_GEN_NEW,
                              "clearRxTxRings() generation bump")
    setup_text = replace_once(setup_text,
        '    RELEASE(rxPool);\n    \n    if (rxBufArrayMem) {',
        '    RELEASE(rxPool);\n    r15PoolFree();\n    \n    if (rxBufArrayMem) {',
        "round15 owned pool teardown")
    write(setup, setup_text)
    print("patched %s" % setup)

    vtd_text = read(vtd)
    vtd_text = replace_once(vtd_text, VTD_GEN_OLD, VTD_GEN_NEW,
                            "rxMapBuffers() generation bump")
    vtd_text = replace_once(vtd_text, VTD_REARM_OLD, VTD_REARM_NEW,
                            "rxInterruptVTD() rearm record")
    write(vtd, vtd_text)
    print("patched %s" % vtd)

    # The new methods go before the final #pragma mark of the file. Appending
    # at EOF is not possible: the upstream file ends with a namespace close.
    anchor = "\n#pragma mark --- statistics update methods ---\n"
    cpp_text = replace_once(cpp_text, anchor,
                            OBS_METHODS + "\n" + RXPOST_METHODS + "\n" +
                                POOL_METHODS + "\n" + TX['METHODS'] + "\n" + anchor.lstrip("\n"),
                            "the methods insertion point")

    cpp_text = TX['patch_cpp'](cpp_text)
    write(cpp, cpp_text)
    print("patched %s" % cpp)
    rx_label = ('native RX normal ring batch16 (ABI3)' if RX_SELECT == '34'
                else 'round-%s RX pool' % RX_SELECT)
    print("applied observation v2, RX post set, %s and round-%s explicit TX mapping"
          % (rx_label, TX_SELECT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
