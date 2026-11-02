/*
 * RTL812xObsLog.hpp -- bounded metadata log recorded INSIDE RTL812xLucy at
 * the driver's real submit and completion sites.
 *
 * WHY THIS EXISTS (round 9)
 * -------------------------
 * Rounds 6-8 answered "which DMA did the device perform in this window" by
 * having a separate probe kext read the driver's descriptor ring from outside.
 * The round-8 report had to admit three limits of that approach:
 *
 *   1. The probe sees the ring AFTER the fact. A slot reused between the
 *      boundary sample and the scan cannot be detected: the probe only knows
 *      `tailAfter`, frozen at the boundary, so it can compute a generation but
 *      cannot prove the bytes it read belong to that generation.
 *   2. A device register naming an address does not prove the memory object is
 *      alive, nor that the PA the probe maps is the driver's ring.
 *   3. Anything the probe cannot decode (TSO MSS, zero length) has to be
 *      guessed, and a guess cannot support a negative claim.
 *
 * So the record is taken at the source. This header is the wire format of a
 * fixed-size, bounded, lock-free log the driver writes at:
 *
 *   - outputStart()  : one record per descriptor it fills   (kObsKindTxSubmit)
 *   - txInterrupt()  : one record per descriptor handed back (kObsKindTxDone)
 *   - rxInterrupt()  : one record per descriptor it reaps     (kObsKindRxDone)
 *
 * The log lives in the driver's OWN live memory object, allocated once in
 * start() and freed in stop(). The driver publishes a copy of it as an
 * IORegistry property, so a reader never dereferences a physical address at
 * all: it receives bytes the driver copied out of the object it still holds.
 * That is the "object or mapping basis" the round-8 report could not supply.
 *
 * CONCURRENCY
 * -----------
 * Writers are the output thread (submit) and the workloop (complete, reap).
 * They can run concurrently, so each writer claims an absolute index with
 * __atomic_fetch_add, fills the record, issues a barrier, and writes `seq`
 * LAST. A reader takes `seq`, reads the body, issues a barrier, and re-reads
 * `seq`: if it changed, the record was being rewritten and is reported as a
 * hole rather than used. `seq` is the absolute index plus one, so it does not
 * repeat until 2^32 records have been written.
 *
 * Nothing here changes how DMA is mapped. The records are ordinary memory
 * writes into a buffer the driver already owns.
 *
 * WIRE FORMAT
 * -----------
 * Host endian, and `recSize`/`version`/`format` are published so a reader that
 * does not recognise them refuses instead of misparsing.
 */

#ifndef RTL812xObsLog_hpp
#define RTL812xObsLog_hpp

/* 'RLO1' little-endian. */
#define kObsMagic        0x314F4C52u
#define kObsVersion      1u
#define kObsFormat       "rtl812x-obs/1"

/* Capacity is a power of two so the index is a mask. 4096 records covers a
 * 3 s window at over a thousand descriptors per second; when it does wrap the
 * reader sees holes and says so, because every record carries its own seq. */
#define kObsCapacity     4096u
#define kObsCapacityMask (kObsCapacity - 1u)

/* How many records the driver copies into the published property. Bounded so
 * the IORegistry blob stays small; `head`, `published` and `wrapped` are
 * published alongside so a reader can tell that it received a suffix. */
#define kObsPublishMax   512u

enum {
    kObsKindNone       = 0,
    kObsKindTxSubmit   = 1,   /* outputStart() filled a descriptor */
    kObsKindTxDone     = 2,   /* txInterrupt() handed a descriptor back */
    kObsKindRxDone     = 3,   /* rxInterrupt() reaped a descriptor */
    kObsKindTxDoorbell = 4    /* outputStart() rang the tail pointer */
};

/* Record flags. */
enum {
    kObsFlagLenUnknown = 1u << 0,  /* length field is not the real length */
    kObsFlagTso        = 1u << 1,  /* GiantSend / LargeSend was set */
    kObsFlagFirstFrag  = 1u << 2,
    kObsFlagLastFrag   = 1u << 3,
    kObsFlagRingEnd    = 1u << 4,
    kObsFlagDescOwn    = 1u << 5,  /* DescOwn was set in the value recorded */
    kObsFlagRxError    = 1u << 6   /* RX descriptor carried RxRES */
};

struct RtlObsHdr {
    UInt32 magic;
    UInt32 version;
    UInt32 recSize;
    UInt32 capacity;
    volatile UInt32 head;   /* records ever written; absolute index = head-1 */
    UInt32 wrapped;         /* records whose slot was overwritten before a
                             * reader could see them */
    UInt64 tStart;          /* mach_absolute_time when the log was created */
    UInt64 published;       /* records copied into the last publication */
    UInt64 reserved;
};

struct RtlObsRec {
    UInt64 tMono;        /* mach_absolute_time at the record site */
    UInt64 addr;         /* descriptor addr field, raw */
    UInt32 seq;          /* absolute index + 1, written LAST */
    UInt32 kind;         /* kObsKind* */
    UInt32 cumulative;   /* driver cumulative index for this record */
    UInt32 slot;         /* descriptor index within the ring */
    UInt32 gen;          /* cumulative / kNumTxDesc for TX; reap index for RX */
    UInt32 batch;        /* first descriptor's cumulative index of this packet */
    UInt32 opts1;        /* raw opts1 (TX) or rx blen low word (RX) */
    UInt32 opts2;        /* raw opts2 (TX) or rx opts2 (RX) */
    UInt32 len;          /* real length, MSS when TSO, or rx length field */
    UInt32 flags;        /* kObsFlag* */
};

/* Total bytes the driver allocates. A macro so the allocation and the
 * published length cannot drift apart. */
#define kObsRegionBytes \
    ((UInt64)sizeof(RtlObsHdr) + (UInt64)kObsCapacity * (UInt64)sizeof(RtlObsRec))

#endif /* RTL812xObsLog_hpp */
