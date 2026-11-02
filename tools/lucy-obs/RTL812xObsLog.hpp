/*
 * RTL812xObsLog.hpp -- bounded metadata log recorded INSIDE RTL812xLucy at
 * the driver's real submit and completion sites.
 *
 * ===========================================================================
 * VERSION 2 (round 10). WHAT WAS WRONG WITH VERSION 1, AND WHY IT MATTERS
 * ===========================================================================
 *
 * Round 9 shipped version 1 of this header. Reviewing it against its own
 * claims found four defects that made the round-9 evidence weaker than the
 * report said. They are fixed here, and each fix is named.
 *
 * (1) THE SEQ FIELD WAS NOT A SEQLOCK.
 *
 *     v1 wrote `seq` ONCE, at the end:
 *
 *         r->tMono = ...;  r->addr = ...;  ... ; fence; r->seq = absolute+1;
 *
 *     A reader took seq, read the body, re-read seq. But because the writer
 *     never marks the slot busy, a reader that arrives while the body is
 *     half-written sees:
 *
 *         seq0 = OLD (the writer has not updated it yet)
 *         body = MIXED (part old, part new)
 *         seq1 = OLD (still not updated)
 *
 *     seq0 == seq1, so v1 reports valid = true for a body that was never
 *     written by any single writer. That is the exact failure a seqlock
 *     exists to prevent, and v1 has it.
 *
 *     v2 marks the slot busy BEFORE touching the body, and uses a ticket:
 *
 *         seq = ticket * 2 + 1   while the body is being written
 *         seq = ticket * 2       once the body is complete (release)
 *
 *     A reader that sees an odd seq refuses. A reader that sees an even seq,
 *     reads the body and re-reads the same even seq knows the body was
 *     complete at both ends of the read.
 *
 * (2) SLOT REUSE AND MULTIPLE WRITERS WERE NOT HANDLED.
 *
 *     Two writers can claim the same slot (absolute indices that differ by
 *     kObsCapacity). v1 let both write the same 56 bytes; the loser then
 *     overwrote the winner's body and stamped its own seq, so the slot could
 *     end up with writer A's body and writer B's seq.
 *
 *     v2 claims the slot with an atomic exchange and RE-CHECKS ownership
 *     before publishing the body:
 *
 *         prev = atomic_exchange(&r->seq, myTicket*2 + 1)
 *         ... write body ...
 *         if (atomic_load(&r->seq) != myTicket*2 + 1) { dropped++; return; }
 *         atomic_store_release(&r->seq, myTicket*2)
 *
 *     A writer that lost the slot does not publish and does not stamp. The
 *     winner's record survives intact. `dropped` counts the loss so it is
 *     visible rather than silent.
 *
 *     TICKETS START AT 1, NOT 0. With a 0-based ticket the very first record
 *     the driver ever writes would have seq == 0, which is also the value a
 *     never-written slot holds. A reader could not tell "the first record" from
 *     "an untouched slot". Starting at 1 makes seq == 0 mean exactly one thing:
 *     this slot has never held a published record. The host regression caught
 *     this; it is fixed here rather than worked around in the reader.
 *
 * (3) THE HEADER AND THE RECORDS COULD COME FROM DIFFERENT PUBLICATIONS.
 *
 *     v1 published `rtl812x-obs-head`, `-first`, `-published`, `-wrapped`,
 *     `-t-published` as five separate OSString properties and the records as
 *     a sixth OSData property. IORegistry property writes are individually
 *     atomic but the six are not atomic as a group, so a reader could get
 *     head from publication N and records from publication N-1.
 *
 *     Round 9's own archive shows this: props.txt records head=0x13c with
 *     t-published = 39963682435 ns, while the archived driver-obs.txt holds
 *     head=0x279 with t-published = 126977397680 ns. Those are two different
 *     publications, 87 s apart, and the report treated the later one as if
 *     it were the one the probe used.
 *
 *     v2 puts ONE self-describing snapshot -- header, identity, epoch,
 *     publication id, sequence range, counts and the records -- into a
 *     single OSData property. There is exactly one property to read, so
 *     there is nothing left to tear.
 *
 * (4) NOTHING IDENTIFIED THE DEVICE, THE LOG EPOCH OR THE PUBLICATION.
 *
 *     v2's header carries vendor/device id, bus:dev:fn, the MAC, the BSD
 *     unit, a driver-instance epoch and a monotonically increasing
 *     publication id. A reader can therefore refuse a snapshot that came
 *     from a different device, a previous driver load, or an older
 *     publication than the one it needs.
 *
 * ===========================================================================
 * BUSINESS CORRELATION (new in v2)
 * ===========================================================================
 *
 * Round 9 could not join a driver record to a client request. Its records
 * carry only queue indices (cumulative/slot/gen/batch) and raw descriptor
 * words, so the report's "this 42-byte DMA is that TCP ACK" was a
 * time-order guess.
 *
 * v2 extracts a business identifier from the packet itself, while the driver
 * still holds the mbuf, and stores it in the record:
 *
 *   - only for a single, unfragmented IPv4/UDP datagram with no IP options
 *     and no VLAN tag, so the payload offset is unambiguous;
 *   - only when the first 4 payload bytes are kObsBizMagic;
 *   - the parse is bounded to kObsBizScanMax bytes of the mbuf chain;
 *   - every failure is recorded as a flag, never as a guess.
 *
 * The record then carries (runToken, reqId, flowHash, pktFlags), and the
 * SAME (runToken, reqId) is written on the RX record of the echoed reply.
 * That is a real join key: two records with the same (runToken, reqId) are
 * the same business operation, and two with different ones are not.
 *
 * A packet the driver could not parse keeps token = 0 and reqId = 0, and
 * kObsPktUnparsed is set. Zero is never a valid token (the load generator
 * starts at 1), so "no token" and "token 1" cannot be confused.
 *
 * ===========================================================================
 * WHAT THIS FILE IS NOT
 * ===========================================================================
 *
 * Nothing here changes how DMA is mapped. The records are ordinary memory
 * writes into a buffer the driver already owns; the publish is one memcpy
 * into a staging buffer and one property set. No device register is touched.
 */

#ifndef RTL812xObsLog_hpp
#define RTL812xObsLog_hpp

/* 'RLO2' little-endian. Version 2 is NOT wire-compatible with version 1:
 * the record grew from 56 to 72 bytes and the header is now inside the
 * published blob instead of being split across properties. A reader that
 * does not recognise the magic/version/recSize refuses. */
#define kObsMagic        0x324F4C52u
#define kObsVersion      2u
#define kObsFormat       "rtl812x-obs/2"

/* Capacity is a power of two so the index is a mask. */
#define kObsCapacity     4096u
#define kObsCapacityMask (kObsCapacity - 1u)

/* How many records one publication carries. Bounded so the property stays
 * small; the header records the ticket range so a reader can tell a complete
 * publication from a truncated one. */
#define kObsPublishMax   512u

/* Business-identifier parsing bounds. */
#define kObsBizMagic        0x31424F49u   /* 'IOB1' */
#define kObsBizScanMax      96u           /* bytes of mbuf chain examined */
#define kObsBizHeaderBytes  14u           /* Ethernet */
#define kObsBizUdpOffset    42u           /* eth 14 + ip 20 + udp 8 */

enum {
    kObsKindNone       = 0,
    kObsKindTxSubmit   = 1,   /* outputStart() filled a descriptor */
    kObsKindTxDone     = 2,   /* txInterrupt() handed a descriptor back */
    kObsKindRxDone     = 3,   /* rxInterrupt() reaped a descriptor */
    kObsKindTxDoorbell = 4    /* outputStart() rang the tail pointer */
};

/* Record flags (descriptor facts). */
enum {
    kObsFlagLenUnknown = 1u << 0,  /* length field is not the real length */
    kObsFlagTso        = 1u << 1,  /* GiantSend / LargeSend was set */
    kObsFlagFirstFrag  = 1u << 2,
    kObsFlagLastFrag   = 1u << 3,
    kObsFlagRingEnd    = 1u << 4,
    kObsFlagDescOwn    = 1u << 5,  /* DescOwn was set in the value recorded */
    kObsFlagRxError    = 1u << 6   /* RX descriptor carried RxRES */
};

/* Record flags (business parsing). Separate word so a descriptor flag and a
 * parse outcome can never be confused by a shift. */
enum {
    kObsPktParsed      = 1u << 0,  /* (token, reqId) are meaningful */
    kObsPktNoMagic     = 1u << 1,  /* payload did not start with the magic */
    kObsPktNotIpv4     = 1u << 2,  /* ethertype was not 0x0800 */
    kObsPktVlan        = 1u << 3,  /* a VLAN tag was present */
    kObsPktFragmented  = 1u << 4,  /* MF set or fragment offset != 0 */
    kObsPktIpOptions   = 1u << 5,  /* IHL != 5 */
    kObsPktNotUdp      = 1u << 6,  /* IP protocol was not 17 */
    kObsPktShort       = 1u << 7,  /* mbuf chain shorter than the header */
    kObsPktTruncated   = 1u << 8,  /* UDP length exceeds the mbuf chain */
    kObsPktNotTx       = 1u << 9,  /* RX record: not a datagram we sent */
    kObsPktTcp         = 1u << 10  /* IPv4/TCP: correlation not attempted */
};

/* ---- wire structs -------------------------------------------------------
 *
 * Every field is host endian: the driver and the reader are the same kernel
 * on the same machine. recSize is published so a mismatch is a refusal.
 */

/* Header, 96 bytes. Lives at offset 0 of the published blob; the records
 * follow it contiguously. */
struct RtlObsHdr {
    UInt32 magic;        /* kObsMagic                                    */
    UInt32 version;      /* kObsVersion                                  */
    UInt32 recSize;      /* sizeof(RtlObsRec)                            */
    UInt32 capacity;     /* kObsCapacity                                 */
    UInt32 head;         /* records ever claimed (absolute)              */
    UInt32 wrapped;      /* slots overwritten before being published     */
    UInt32 dropped;      /* writers that lost their slot (see (2))       */
    UInt32 pubId;        /* publication counter, starts at 1             */
    UInt32 firstTicket;  /* ticket of the first copied record            */
    UInt32 lastTicket;   /* ticket of the last copied record             */
    UInt32 validCount;   /* records copied and verified in this snapshot */
    UInt32 lostCount;    /* holes found while copying this snapshot      */
    UInt32 epoch;        /* driver-instance epoch (seconds since boot)   */
    UInt32 busDevFn;     /* (bus<<8)|(dev<<3)|fn                         */
    UInt32 vendorId;     /* PCI vendor id                                */
    UInt32 deviceId;     /* PCI device id                                */
    UInt32 ifUnit;       /* BSD unit: 2 for en2                          */
    UInt32 macHi;        /* MAC bytes 0..3, big endian in the low 32     */
    UInt32 macLo;        /* MAC bytes 4..5 in the low 16 bits            */
    UInt32 flags;        /* kObsHdrFlag*                                 */
    UInt64 tStart;       /* mach_absolute_time when the log was created  */
    UInt64 tPublished;   /* mach_absolute_time when this snapshot began  */
    UInt64 reserved;
};

/* Header flags. */
enum {
    kObsHdrFlagOverflowed = 1u << 0,  /* head wrapped past capacity at least
                                       * once: the oldest records are gone  */
    kObsHdrFlagLost       = 1u << 1,  /* this snapshot itself has holes    */
    kObsHdrFlagTruncated  = 1u << 2   /* more records existed than were
                                       * copied (kObsPublishMax reached)   */
};

/* One record, 72 bytes (2 x u64 + 14 x u32). */
struct RtlObsRec {
    UInt64 tMono;        /* mach_absolute_time at the record site        */
    UInt64 addr;         /* descriptor addr field, raw                   */
    UInt32 seq;          /* ticket*2 | busy; ticket starts at 1, so 0 is
                          * never a published record. See (2) above.      */
    UInt32 kind;         /* kObsKind*                                    */
    UInt32 cumulative;   /* driver cumulative index for this record      */
    UInt32 slot;         /* descriptor index within the ring             */
    UInt32 gen;          /* cumulative / ring size                       */
    UInt32 batch;        /* first descriptor's cumulative index          */
    UInt32 opts1;        /* raw opts1 (TX) or rx status1 (RX)            */
    UInt32 opts2;        /* raw opts2                                    */
    UInt32 len;          /* real length, MSS when TSO, or rx length      */
    UInt32 flags;        /* kObsFlag*                                    */
    UInt32 token;        /* business run token, 0 = not available        */
    UInt32 reqId;        /* business request id, 0 = not available       */
    UInt32 flowHash;     /* src/dst port + address hash, 0 = not parsed  */
    UInt32 pktFlags;     /* kObsPkt*                                     */
};

#define kObsRecBytes    ((UInt32)sizeof(RtlObsRec))
#define kObsHdrBytes    ((UInt32)sizeof(RtlObsHdr))
#define kObsSnapshotMax ((UInt64)kObsHdrBytes + \
                         (UInt64)kObsPublishMax * (UInt64)sizeof(RtlObsRec))

/* Total bytes the driver allocates for the live ring. A macro so the
 * allocation and the published geometry cannot drift apart. */
#define kObsRegionBytes \
    ((UInt64)sizeof(RtlObsHdr) + (UInt64)kObsCapacity * (UInt64)sizeof(RtlObsRec))

/* ---- small helpers the driver uses -------------------------------------- */

/* Pack a MAC into the header's two words. */
static inline void obsPackMac(const UInt8 *mac, UInt32 *hi, UInt32 *lo) {
    *hi = ((UInt32)mac[0] << 24) | ((UInt32)mac[1] << 16) |
          ((UInt32)mac[2] << 8)  |  (UInt32)mac[3];
    *lo = ((UInt32)mac[4] << 8)  |  (UInt32)mac[5];
}

#endif /* RTL812xObsLog_hpp */
