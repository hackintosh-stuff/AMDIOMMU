// ---- ROUND 10: decoding the driver's own observation log (wire v2) --------
//
// WHY THIS REPLACES THE RING SCAN AS THE PRIMARY BASIS
// ---------------------------------------------------
// The window scan above is still useful: it is the only way to see the ring
// without driver cooperation, and it is what the round-8 evidence rests on.
// But it cannot answer "is this the same generation of bytes" or "what was the
// real length of a TSO segment", because both facts are destroyed by the time
// a reader looks at the ring.
//
// The driver records them at the source. This section decodes those records.
// The format is defined in tools/lucy-obs/RTL812xObsLog.hpp, which is the file
// the driver compiles; the constants below must match it, and obsHeaderOk()
// checks magic/version/record size/capacity so a mismatch is a refusal rather
// than a misparse.
//
// WHAT ROUND 9 GOT WRONG, AND WHAT CHANGED
// ----------------------------------------
//   * v1 published head/first/published/wrapped/t-published as five separate
//     OSString properties plus the records as a sixth OSData. The six are not
//     atomic as a group, so a reader could pair a header from publication N
//     with records from N-1. v2 puts ONE header and the records in a single
//     OSData: there is nothing left to tear.
//   * v1's `seq` was written only at the end, so a reader that arrived
//     mid-write saw the PREVIOUS writer's seq before and after its body read
//     and concluded the body was consistent. v2 marks the slot busy first and
//     uses ticket*2|busy, so an in-flight body is detectable.
//   * v1 had no device identity, no epoch and no publication id. v2 has all
//     three, so a snapshot from another device, another driver load, or an
//     older publication can be refused instead of silently used.
//   * v1 had no business identifier, so a driver record could not be joined to
//     a client request. v2 carries (token, reqId, flowHash, pktFlags) on TX
//     submit, doorbell and RX records.
//
// Every field is host endian: the driver and this reader are the same kernel
// on the same machine.
static const u32 OBS_MAGIC = 0x324F4C52u;   // 'RLO2'
static const u32 OBS_VERSION = 2u;
static const u32 OBS_REC_BYTES = 72u;       // 2 x u64 + 14 x u32
// sizeof(RtlObsHdr): 20 x u32 (80) + 3 x u64 (24) = 104, 8-byte aligned.
// The driver publishes this number too; a mismatch is a refusal, not a
// misparse, so the two files cannot drift apart silently.
static const u32 OBS_HDR_BYTES = 104u;
static const u32 OBS_CAPACITY = 4096u;
static const u32 OBS_PUBLISH_MAX = 512u;

enum {
    OBS_KIND_NONE = 0,
    OBS_KIND_TX_SUBMIT = 1,
    OBS_KIND_TX_DONE = 2,
    OBS_KIND_RX_DONE = 3,
    OBS_KIND_TX_DOORBELL = 4
};

static inline const char *obsKindName(u32 k) {
    switch (k) {
        case OBS_KIND_TX_SUBMIT:   return "tx-submit";
        case OBS_KIND_TX_DONE:     return "tx-done";
        case OBS_KIND_RX_DONE:     return "rx-done";
        case OBS_KIND_TX_DOORBELL: return "tx-doorbell";
        default:                   return "none";
    }
}

enum {
    OBS_FLAG_LEN_UNKNOWN = 1u << 0,
    OBS_FLAG_TSO = 1u << 1,
    OBS_FLAG_FIRST_FRAG = 1u << 2,
    OBS_FLAG_LAST_FRAG = 1u << 3,
    OBS_FLAG_RING_END = 1u << 4,
    OBS_FLAG_DESC_OWN = 1u << 5,
    OBS_FLAG_RX_ERROR = 1u << 6
};

enum {
    OBS_PKT_PARSED = 1u << 0,
    OBS_PKT_NO_MAGIC = 1u << 1,
    OBS_PKT_NOT_IPV4 = 1u << 2,
    OBS_PKT_VLAN = 1u << 3,
    OBS_PKT_FRAGMENTED = 1u << 4,
    OBS_PKT_IP_OPTIONS = 1u << 5,
    OBS_PKT_NOT_UDP = 1u << 6,
    OBS_PKT_SHORT = 1u << 7,
    OBS_PKT_TRUNCATED = 1u << 8,
    OBS_PKT_NOT_TX = 1u << 9,
    OBS_PKT_TCP = 1u << 10
};

enum {
    OBS_HDR_OVERFLOWED = 1u << 0,
    OBS_HDR_LOST = 1u << 1,
    OBS_HDR_TRUNCATED = 1u << 2
};

// One decoded record. Field order mirrors RtlObsRec.
struct ObsRec {
    u64  tMono;
    u64  addr;
    u32  seq;
    u32  kind;
    u32  cumulative;
    u32  slot;
    u32  gen;
    u32  batch;
    u32  opts1;
    u32  opts2;
    u32  len;
    u32  flags;
    u32  token;
    u32  reqId;
    u32  flowHash;
    u32  pktFlags;
    bool valid;      // this record's ticket matched and its seq was even
};

static inline u32 obsRd32(const u8 *p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) |
           ((u32)p[3] << 24);
}

static inline u64 obsRd64(const u8 *p) {
    return (u64)obsRd32(p) | ((u64)obsRd32(p + 4) << 32);
}

// Header of the published snapshot.
//
// This is decoded from the SAME buffer as the records, which is the whole
// point: there is no window in which the header can describe one publication
// and the records another.
struct ObsHeader {
    u32  magic;
    u32  version;
    u32  recSize;
    u32  capacity;
    u32  head;
    u32  wrapped;
    u32  dropped;
    u32  pubId;
    u32  firstTicket;
    u32  lastTicket;
    u32  validCount;
    u32  lostCount;
    u32  epoch;
    u32  busDevFn;
    u32  vendorId;
    u32  deviceId;
    u32  ifUnit;
    u32  macHi;
    u32  macLo;
    u32  flags;
    u64  tStart;
    u64  tPublished;
    u32  recordCount;    // derived: (bytes - hdrBytes) / recSize
    bool ok;
    const char *why;
};

static inline ObsHeader obsHeaderOk(const u8 *blob, u64 bytes) {
    ObsHeader h;
    h.magic = 0; h.version = 0; h.recSize = 0; h.capacity = 0;
    h.head = 0; h.wrapped = 0; h.dropped = 0; h.pubId = 0;
    h.firstTicket = 0; h.lastTicket = 0; h.validCount = 0; h.lostCount = 0;
    h.epoch = 0; h.busDevFn = 0; h.vendorId = 0; h.deviceId = 0;
    h.ifUnit = 0; h.macHi = 0; h.macLo = 0; h.flags = 0;
    h.tStart = 0; h.tPublished = 0; h.recordCount = 0;
    h.ok = false;
    h.why = "not published";
    if (!blob) return h;
    if (bytes < (u64)OBS_HDR_BYTES) { h.why = "shorter than a header"; return h; }

    h.magic       = obsRd32(blob + 0);
    h.version     = obsRd32(blob + 4);
    h.recSize     = obsRd32(blob + 8);
    h.capacity    = obsRd32(blob + 12);
    h.head        = obsRd32(blob + 16);
    h.wrapped     = obsRd32(blob + 20);
    h.dropped     = obsRd32(blob + 24);
    h.pubId       = obsRd32(blob + 28);
    h.firstTicket = obsRd32(blob + 32);
    h.lastTicket  = obsRd32(blob + 36);
    h.validCount  = obsRd32(blob + 40);
    h.lostCount   = obsRd32(blob + 44);
    h.epoch       = obsRd32(blob + 48);
    h.busDevFn    = obsRd32(blob + 52);
    h.vendorId    = obsRd32(blob + 56);
    h.deviceId    = obsRd32(blob + 60);
    h.ifUnit      = obsRd32(blob + 64);
    h.macHi       = obsRd32(blob + 68);
    h.macLo       = obsRd32(blob + 72);
    h.flags       = obsRd32(blob + 76);
    h.tStart      = obsRd64(blob + 80);
    h.tPublished  = obsRd64(blob + 88);
    // 96..103 is `reserved` in the driver's struct; not decoded here.

    if (h.magic != OBS_MAGIC)   { h.why = "bad magic"; return h; }
    if (h.version != OBS_VERSION) { h.why = "unknown version"; return h; }
    if (h.recSize != OBS_REC_BYTES) { h.why = "record size mismatch"; return h; }
    if (h.capacity != OBS_CAPACITY) { h.why = "capacity mismatch"; return h; }

    const u64 body = bytes - (u64)OBS_HDR_BYTES;
    if ((body % (u64)h.recSize) != 0) { h.why = "ragged record body"; return h; }
    const u64 n = body / (u64)h.recSize;
    if (n > (u64)OBS_PUBLISH_MAX) { h.why = "more records than a publish holds"; return h; }
    if (n > (u64)h.capacity) { h.why = "more records than the ring holds"; return h; }
    h.recordCount = (u32)n;

    if (h.validCount > h.recordCount) { h.why = "valid count exceeds records"; return h; }
    if (h.lostCount > h.recordCount)  { h.why = "lost count exceeds records"; return h; }
    if (h.validCount + h.lostCount != h.recordCount) {
        h.why = "valid + lost does not equal the record count";
        return h;
    }
    if (h.recordCount > 0) {
        if (h.lastTicket < h.firstTicket) { h.why = "ticket range inverted"; return h; }
        if ((h.lastTicket - h.firstTicket + 1u) != h.recordCount) {
            h.why = "ticket range does not span the record count";
            return h;
        }
        if (h.head < h.lastTicket + 1u) { h.why = "head is behind the last ticket"; return h; }
    }
    if (h.tPublished < h.tStart) { h.why = "published before the log existed"; return h; }
    if (h.pubId == 0) { h.why = "publication id is zero"; return h; }

    h.ok = true;
    h.why = "ok";
    return h;
}

// The device identity a reader demands. Filled from the probe's own view of
// the PCI function it is driving the experiment against; a snapshot that does
// not match is refused rather than attributed to the wrong device.
struct ObsIdentity {
    u32  busDevFn;
    u32  vendorId;
    u32  deviceId;
    u32  ifUnit;
    u32  macHi;
    u32  macLo;
    u32  epoch;        // 0 = do not check
    bool have;         // false = identity checks are N/A, not PASS
};

// Returns true when the snapshot's identity matches what the reader demands.
// `why` is set to a stable token on refusal so the analyser can assert on the
// REASON rather than just on a non-zero exit.
static inline bool obsIdentityMatches(const ObsHeader &h,
                                      const ObsIdentity &want,
                                      const char **why) {
    if (why) *why = "ok";
    if (!want.have) { if (why) *why = "identity-not-declared"; return false; }
    if (h.busDevFn != want.busDevFn) { if (why) *why = "bdf-mismatch"; return false; }
    if (h.vendorId != want.vendorId) { if (why) *why = "vendor-mismatch"; return false; }
    if (h.deviceId != want.deviceId) { if (why) *why = "device-mismatch"; return false; }
    if (h.ifUnit != want.ifUnit)     { if (why) *why = "interface-unit-mismatch"; return false; }
    if (h.macHi != want.macHi || h.macLo != want.macLo) {
        if (why) *why = "mac-mismatch"; return false;
    }
    if (want.epoch != 0 && h.epoch != want.epoch) {
        if (why) *why = "epoch-mismatch"; return false;
    }
    return true;
}

// Read one record out of the published snapshot.
//
// The snapshot is a COPY, so the seqlock's live-tear check has already been
// done by the driver at publish time (obsPublish() re-validates each record's
// seq against its ticket after copying). What this function checks is the
// remaining invariant: the record's own seq must be EVEN and must equal
// ticket*2, i.e. it must be a complete, published record of the ticket the
// snapshot claims for that position. Anything else is a hole and is reported
// as invalid rather than used.
static inline ObsRec obsReadRecAt(const u8 *blob, const ObsHeader &h,
                                  u32 index) {
    ObsRec r;
    r.tMono = 0; r.addr = 0; r.seq = 0; r.kind = 0;
    r.cumulative = 0; r.slot = 0; r.gen = 0; r.batch = 0;
    r.opts1 = 0; r.opts2 = 0; r.len = 0; r.flags = 0;
    r.token = 0; r.reqId = 0; r.flowHash = 0; r.pktFlags = 0;
    r.valid = false;
    if (!blob || !h.ok || index >= h.recordCount) return r;

    const u8 *rec = blob + (u64)OBS_HDR_BYTES + (u64)index * (u64)h.recSize;
    const u32 seq = obsRd32(rec + 16);
    if (seq == 0) return r;                 // explicit hole
    if ((seq & 1u) != 0) return r;          // still marked busy: refuse
    const u32 ticket = h.firstTicket + index;
    if ((seq >> 1) != ticket) return r;     // belongs to a different ticket

    r.tMono      = obsRd64(rec + 0);
    r.addr       = obsRd64(rec + 8);
    r.seq        = seq;
    r.kind       = obsRd32(rec + 20);
    r.cumulative = obsRd32(rec + 24);
    r.slot       = obsRd32(rec + 28);
    r.gen        = obsRd32(rec + 32);
    r.batch      = obsRd32(rec + 36);
    r.opts1      = obsRd32(rec + 40);
    r.opts2      = obsRd32(rec + 44);
    r.len        = obsRd32(rec + 48);
    r.flags      = obsRd32(rec + 52);
    r.token      = obsRd32(rec + 56);
    r.reqId      = obsRd32(rec + 60);
    r.flowHash   = obsRd32(rec + 64);
    r.pktFlags   = obsRd32(rec + 68);
    r.valid = true;
    return r;
}

// ---- joining submit records to completion records ------------------------
//
// This is the correspondence the task asks for, and it is exact: the driver
// writes the SAME cumulative index in the submit record and in the completion
// record, because both come from its own counters (txTailPtr0 and txClosePtr0)
// which are the numbers the hardware reports back. No inference about slot
// reuse is involved -- the join key is not the slot.
struct ObsTxOp {
    u32  cumulative;
    u32  slot;
    u32  gen;
    u64  submitAddr;
    u32  submitLen;
    u32  submitFlags;
    u64  tSubmit;
    u64  tDoorbell;    // 0 when the doorbell record was not seen
    bool haveSubmit;
    bool haveDone;
    u64  tDone;
    u32  token;        // business id carried by the submit record
    u32  reqId;
    u32  flowHash;
    u32  pktFlags;
};

static const u32 OBS_MAX_OPS = 64;
// A single controlled request is one small datagram, so it fits in one or two
// segments. Eight is generous and keeps the per-op record bounded.
static const u32 OBS_MAX_SEGS = 8;
static const u32 OBS_MAX_BIZ_OPS = 24;

// One business operation: every TX segment that carried it, the doorbell that
// released them, the completions that returned them, and the RX record of the
// echo. This is the unit the task's "unique request <-> TX/RX DMA records"
// question is answered in.
struct ObsBizOp {
    u32  token;
    u32  reqId;
    u32  flowHash;
    u32  segCount;       // TX submit records with this (token, reqId)
    u32  segCapped;      // segments beyond OBS_MAX_SEGS (truncation, not loss)
    u32  segCum[OBS_MAX_SEGS];
    u64  segAddr[OBS_MAX_SEGS];
    u32  segLen[OBS_MAX_SEGS];
    u32  segDone;        // segments whose completion was seen
    u64  tSubmitFirst;
    u64  tSubmitLast;
    u64  tDoorbell;
    u64  tDoneFirst;
    u64  tDoneLast;
    bool haveSubmit;
    bool haveDoorbell;
    bool haveDone;       // at least one completion
    bool allSegDone;     // every segment completed
    bool haveRx;
    u32  rxCum;
    u64  rxAddr;
    u32  rxLen;
    u64  tRx;
};

// Why a snapshot does or does not cover the measurement window.
enum {
    OBS_COVER_NONE = 0,       // no usable snapshot
    OBS_COVER_TOO_LATE = 1,   // snapshot published before the window ended
    OBS_COVER_TOO_EARLY = 2,  // snapshot does not reach back to the window start
    OBS_COVER_HOLES = 3,      // records inside the window are missing
    OBS_COVER_OVERFLOW = 4,   // the ring wrapped past records in the window
    OBS_COVER_EPOCH = 5,      // snapshot is from another driver instance
    OBS_COVER_IDENTITY = 6,   // snapshot is from another device
    OBS_COVER_FULL = 7        // all of the above hold
};

static inline const char *obsCoverName(u32 c) {
    switch (c) {
        case OBS_COVER_TOO_LATE:   return "published-before-window-end";
        case OBS_COVER_TOO_EARLY:  return "does-not-reach-window-start";
        case OBS_COVER_HOLES:      return "records-missing-inside-window";
        case OBS_COVER_OVERFLOW:   return "ring-overflowed-past-window";
        case OBS_COVER_EPOCH:      return "driver-epoch-mismatch";
        case OBS_COVER_IDENTITY:   return "device-identity-mismatch";
        case OBS_COVER_FULL:       return "full";
        default:                   return "none";
    }
}

struct ObsJoin {
    // ---- whole-snapshot counters ----
    u32  records;         // records present in the snapshot
    u32  holes;           // records the reader refused
    u32  submits;
    u32  dones;
    u32  doorbells;
    u32  rxDone;
    u32  rxAddrZero;
    u32  rxParsed;        // RX records that carried a business id
    u32  txParsed;        // TX submit records that carried a business id
    u32  staleRecords;    // == holes, kept for the older property names
    u32  unmatchedDone;   // completion with no submit anywhere in the snapshot
    u32  uncompletedSubmit;  // submit with no completion anywhere in the snapshot
    u32  overflow;        // ops beyond OBS_MAX_OPS
    u64  firstSubmitT;
    u64  lastDoneT;
    u64  firstRxAddr;
    u64  lastRxAddr;
    u32  rxLenSum;

    // ---- window subset ----
    //
    // The published log covers several seconds, of which the measurement
    // window is only the middle three. These count only the operations whose
    // submit AND completion both fall inside [winStart, winEnd].
    u32  winSubmits;
    u32  winDones;
    u32  winPaired;          // both ends inside the window
    u32  winOrphanDone;      // completion inside the window, submit NOWHERE
    u32  winPreWindowInFlight; // completion inside, submit BEFORE the window
    u32  winUncompleted;     // submitted inside, still in flight at window end

    // ---- the three separate verdicts the task requires ----
    //
    // These are deliberately independent. "One pair succeeded" must not be
    // able to stand in for "the records cover the window", and neither of
    // those may stand in for "the controlled batch finished".
    bool hasCompletePair;      // >= 1 verifiable submit/complete pair
    bool recordsCoverWindow;   // raw records completely cover [winStart,winEnd]
    bool controlledBatchComplete;  // every expected request of this batch done
    u32  coverState;           // OBS_COVER_*
    const char *coverWhy;

    // The first window-internal pair, which is the one a report quotes.
    bool haveWinOp;
    ObsTxOp winOp;

    // ---- business correlation ----
    ObsBizOp biz[OBS_MAX_BIZ_OPS];
    u32  bizCount;
    u32  bizCapped;        // operations beyond OBS_MAX_BIZ_OPS
    u32  expectedBatch;    // declared expected request count (0 = undeclared)
    u32  batchComplete;    // requests of this batch with TX+done+RX
    u32  batchPartial;     // requests with some but not all of the three
    u32  batchMissing;     // declared requests with no record at all
    u32  batchUnexpected;  // records for requests outside the declared range
    u32  batchUnparsed;    // TX/RX records that carried no business id
    const char *batchWhy;

    // ---- per-op array kept for the aggregate counters ----
    ObsTxOp op[OBS_MAX_OPS];
    u32  n;
};

// Fold the published snapshot into a submit/complete correspondence and the
// three verdicts.
//
// ROUND 10: this fills `j` IN PLACE rather than returning by value. ObsJoin is
// large; returning it puts a temporary of that size on the caller's stack,
// which pushed m2b2ReadDriverObs() past the 4 KiB frame threshold and made
// clang emit a WEAK ____chkstk_darwin reference -- which kmutil refuses with
// "Has weak references but does not test for them."
static inline void obsJoinInto(ObsJoin &j, const u8 *blob, u64 bytes,
                               u32 ringSize, u64 winStart, u64 winEnd,
                               u32 expectedBatch) {
    j.records = 0; j.holes = 0;
    j.submits = 0; j.dones = 0; j.doorbells = 0;
    j.rxDone = 0; j.rxAddrZero = 0; j.rxParsed = 0; j.txParsed = 0;
    j.staleRecords = 0; j.unmatchedDone = 0; j.uncompletedSubmit = 0;
    j.overflow = 0;
    j.firstSubmitT = 0; j.lastDoneT = 0;
    j.firstRxAddr = 0; j.lastRxAddr = 0; j.rxLenSum = 0;
    j.winSubmits = 0; j.winDones = 0; j.winPaired = 0;
    j.winOrphanDone = 0; j.winPreWindowInFlight = 0; j.winUncompleted = 0;
    j.hasCompletePair = false;
    j.recordsCoverWindow = false;
    j.controlledBatchComplete = false;
    j.coverState = OBS_COVER_NONE;
    j.coverWhy = "no-snapshot";
    j.haveWinOp = false;
    j.n = 0;
    j.bizCount = 0; j.bizCapped = 0;
    j.expectedBatch = expectedBatch;
    j.batchComplete = 0; j.batchPartial = 0;
    j.batchMissing = 0; j.batchUnexpected = 0; j.batchUnparsed = 0;
    j.batchWhy = "no-snapshot";
    j.winOp.cumulative = 0; j.winOp.slot = 0; j.winOp.gen = 0;
    j.winOp.submitAddr = 0; j.winOp.submitLen = 0; j.winOp.submitFlags = 0;
    j.winOp.tSubmit = 0; j.winOp.tDoorbell = 0;
    j.winOp.haveSubmit = false; j.winOp.haveDone = false; j.winOp.tDone = 0;
    j.winOp.token = 0; j.winOp.reqId = 0; j.winOp.flowHash = 0;
    j.winOp.pktFlags = 0;

    const ObsHeader h = obsHeaderOk(blob, bytes);
    if (!h.ok) { j.coverWhy = h.why; j.batchWhy = h.why; return; }
    j.records = h.recordCount;
    j.recordsCoverWindow = false;
    j.coverState = OBS_COVER_NONE;

    // Pass 1: submits. `op[]` keeps a WINDOW-PREFERRED subset.
    const bool haveWin = (winStart != 0 && winEnd > winStart);
    for (u32 i = 0; i < h.recordCount; i++) {
        const ObsRec r = obsReadRecAt(blob, h, i);
        if (!r.valid) { j.holes++; j.staleRecords++; continue; }
        if (r.kind == OBS_KIND_TX_SUBMIT) {
            j.submits++;
            if (r.pktFlags & OBS_PKT_PARSED) j.txParsed++;
            else j.batchUnparsed++;
            if (j.firstSubmitT == 0 || r.tMono < j.firstSubmitT)
                j.firstSubmitT = r.tMono;
            const bool inWin = (!haveWin ||
                                (r.tMono >= winStart && r.tMono <= winEnd));
            if (!inWin) continue;    // outside the window: not kept, not a loss
            if (j.n < OBS_MAX_OPS) {
                ObsTxOp &o = j.op[j.n];
                o.cumulative = r.cumulative;
                o.slot = r.slot;
                o.gen = (ringSize ? r.cumulative / ringSize : r.gen);
                o.submitAddr = r.addr;
                o.submitLen = r.len;
                o.submitFlags = r.flags;
                o.tSubmit = r.tMono;
                o.tDoorbell = 0;
                o.haveSubmit = true;
                o.haveDone = false;
                o.tDone = 0;
                o.token = r.token;
                o.reqId = r.reqId;
                o.flowHash = r.flowHash;
                o.pktFlags = r.pktFlags;
                j.n++;
            } else {
                j.overflow++;
            }
        } else if (r.kind == OBS_KIND_RX_DONE) {
            j.rxDone++;
            if (r.addr == 0) j.rxAddrZero++;
            if (r.pktFlags & OBS_PKT_PARSED) j.rxParsed++;
            if (j.firstRxAddr == 0) j.firstRxAddr = r.addr;
            j.lastRxAddr = r.addr;
            j.rxLenSum += r.len;
        }
    }

    // Pass 2: completions and doorbells.
    for (u32 i = 0; i < h.recordCount; i++) {
        const ObsRec r = obsReadRecAt(blob, h, i);
        if (!r.valid) continue;
        if (r.kind == OBS_KIND_TX_DONE) {
            j.dones++;
            if (r.tMono > j.lastDoneT) j.lastDoneT = r.tMono;
            bool matched = false;
            for (u32 k = 0; k < j.n; k++) {
                if (j.op[k].cumulative == r.cumulative) {
                    j.op[k].haveDone = true;
                    j.op[k].tDone = r.tMono;
                    matched = true;
                    break;
                }
            }
            if (!matched) j.unmatchedDone++;
        } else if (r.kind == OBS_KIND_TX_DOORBELL) {
            j.doorbells++;
            for (u32 k = 0; k < j.n; k++) {
                if (!j.op[k].haveDone && j.op[k].tDoorbell == 0 &&
                    j.op[k].cumulative < r.cumulative) {
                    j.op[k].tDoorbell = r.tMono;
                }
            }
        }
    }

    for (u32 k = 0; k < j.n; k++) {
        if (!j.op[k].haveDone) j.uncompletedSubmit++;
    }

    // ---- verdict 1: has_complete_pair ----
    //
    // At least one operation whose submit AND completion are both visible in
    // this snapshot. That is the weakest of the three claims and it is the
    // only one round 9 actually established.
    for (u32 k = 0; k < j.n; k++) {
        if (j.op[k].haveSubmit && j.op[k].haveDone) {
            j.hasCompletePair = true;
            break;
        }
    }

    // ---- the window subset ----
    if (haveWin) {
        for (u32 k = 0; k < j.n; k++) {
            const ObsTxOp &o = j.op[k];
            const bool subIn = (o.tSubmit >= winStart && o.tSubmit <= winEnd);
            const bool doneIn = (o.haveDone && o.tDone >= winStart &&
                                 o.tDone <= winEnd);
            if (subIn) j.winSubmits++;
            if (doneIn) {
                j.winDones++;
                if (subIn) {
                    j.winPaired++;
                    if (!j.haveWinOp) {
                        j.winOp = o;
                        j.haveWinOp = true;
                    }
                } else {
                    // A completion inside the window whose submit is before it:
                    // that is a legitimate pre-window in-flight item, and it is
                    // NOT an orphan. Distinguishing these two is the point.
                    if (o.haveSubmit) j.winPreWindowInFlight++;
                    else               j.winOrphanDone++;
                }
            }
            if (subIn && !o.haveDone) j.winUncompleted++;
        }
    }

    // ---- verdict 2: records_cover_window ----
    //
    // This asks a completely different question from verdict 1: do the RAW
    // records cover the whole time range, with nothing missing inside it?
    //
    // Four independent ways to fail, each reported separately:
    //   * the snapshot was taken before the window ended, so the tail of the
    //     window was never in it (round 9 failed exactly here: published at
    //     39963682435 ns, window ended at 40494639566 ns, 0.53 s short);
    //   * the snapshot does not reach back to the window start;
    //   * there are holes inside the window;
    //   * the ring overflowed, so records that WOULD have been inside it were
    //     overwritten before the snapshot was taken.
    if (!haveWin) {
        j.coverState = OBS_COVER_NONE;
        j.coverWhy = "no-window-declared";
    } else if (h.tPublished < winEnd) {
        j.coverState = OBS_COVER_TOO_LATE;
        j.coverWhy = "published-before-window-end";
    } else if ((h.flags & OBS_HDR_OVERFLOWED) != 0) {
        j.coverState = OBS_COVER_OVERFLOW;
        j.coverWhy = "ring-overflowed-past-window";
    } else if (j.holes != 0) {
        j.coverState = OBS_COVER_HOLES;
        j.coverWhy = "records-missing-inside-window";
    } else {
        // The snapshot must reach back to (or before) the window start. The
        // oldest record it holds is the one at firstTicket; if that record is
        // already INSIDE the window, the part of the window before it was
        // never captured.
        u64 oldest = 0;
        for (u32 i = 0; i < h.recordCount; i++) {
            const ObsRec r = obsReadRecAt(blob, h, i);
            if (!r.valid) continue;
            if (oldest == 0 || r.tMono < oldest) oldest = r.tMono;
        }
        if (oldest == 0 || oldest > winStart) {
            j.coverState = OBS_COVER_TOO_EARLY;
            j.coverWhy = "does-not-reach-window-start";
        } else {
            j.coverState = OBS_COVER_FULL;
            j.coverWhy = "full";
            j.recordsCoverWindow = true;
        }
    }

    // ---- verdict 3: controlled_batch_complete ----
    //
    // The finite batch this round actually sends. Every declared request id
    // must have: at least one TX submit record, a completion for EVERY one of
    // its segments, and an RX record carrying the same (token, reqId).
    //
    // This is what makes "the request went out through this device and the
    // reply came back through it" a fact rather than an inference.
    for (u32 i = 0; i < h.recordCount; i++) {
        const ObsRec r = obsReadRecAt(blob, h, i);
        if (!r.valid) continue;
        if ((r.pktFlags & OBS_PKT_PARSED) == 0) continue;
        if (r.kind != OBS_KIND_TX_SUBMIT && r.kind != OBS_KIND_TX_DOORBELL &&
            r.kind != OBS_KIND_RX_DONE) continue;

        // Find or create the operation.
        ObsBizOp *b = nullptr;
        for (u32 k = 0; k < j.bizCount; k++) {
            if (j.biz[k].token == r.token && j.biz[k].reqId == r.reqId) {
                b = &j.biz[k];
                break;
            }
        }
        if (!b) {
            if (j.bizCount >= OBS_MAX_BIZ_OPS) { j.bizCapped++; continue; }
            b = &j.biz[j.bizCount++];
            b->token = r.token;
            b->reqId = r.reqId;
            b->flowHash = r.flowHash;
            b->segCount = 0; b->segCapped = 0; b->segDone = 0;
            b->tSubmitFirst = 0; b->tSubmitLast = 0; b->tDoorbell = 0;
            b->tDoneFirst = 0; b->tDoneLast = 0;
            b->haveSubmit = false; b->haveDoorbell = false;
            b->haveDone = false; b->allSegDone = false;
            b->haveRx = false; b->rxCum = 0; b->rxAddr = 0;
            b->rxLen = 0; b->tRx = 0;
            for (u32 s = 0; s < OBS_MAX_SEGS; s++) {
                b->segCum[s] = 0; b->segAddr[s] = 0; b->segLen[s] = 0;
            }
        }

        if (r.kind == OBS_KIND_TX_SUBMIT) {
            b->haveSubmit = true;
            if (b->tSubmitFirst == 0 || r.tMono < b->tSubmitFirst)
                b->tSubmitFirst = r.tMono;
            if (r.tMono > b->tSubmitLast) b->tSubmitLast = r.tMono;
            if (b->segCount < OBS_MAX_SEGS) {
                b->segCum[b->segCount] = r.cumulative;
                b->segAddr[b->segCount] = r.addr;
                b->segLen[b->segCount] = r.len;
                b->segCount++;
            } else {
                b->segCapped++;
            }
        } else if (r.kind == OBS_KIND_TX_DOORBELL) {
            b->haveDoorbell = true;
            b->tDoorbell = r.tMono;
        } else {   // OBS_KIND_RX_DONE
            b->haveRx = true;
            b->rxCum = r.cumulative;
            b->rxAddr = r.addr;
            b->rxLen = r.len;
            b->tRx = r.tMono;
        }
    }

    // Attach completions to business ops by cumulative index.
    for (u32 i = 0; i < h.recordCount; i++) {
        const ObsRec r = obsReadRecAt(blob, h, i);
        if (!r.valid || r.kind != OBS_KIND_TX_DONE) continue;
        for (u32 k = 0; k < j.bizCount; k++) {
            ObsBizOp &b = j.biz[k];
            for (u32 s = 0; s < b.segCount; s++) {
                if (b.segCum[s] == r.cumulative) {
                    b.segDone++;
                    b.haveDone = true;
                    if (b.tDoneFirst == 0 || r.tMono < b.tDoneFirst)
                        b.tDoneFirst = r.tMono;
                    if (r.tMono > b.tDoneLast) b.tDoneLast = r.tMono;
                    break;
                }
            }
        }
    }
    for (u32 k = 0; k < j.bizCount; k++) {
        ObsBizOp &b = j.biz[k];
        b.allSegDone = (b.haveSubmit && b.segCount > 0 &&
                        b.segDone == b.segCount && b.segCapped == 0);
    }

    // Count the batch outcomes.
    for (u32 k = 0; k < j.bizCount; k++) {
        const ObsBizOp &b = j.biz[k];
        const bool inRange = (expectedBatch != 0 && b.reqId >= 1 &&
                              b.reqId <= expectedBatch);
        if (expectedBatch != 0 && !inRange) { j.batchUnexpected++; continue; }
        if (b.haveSubmit && b.allSegDone && b.haveRx) j.batchComplete++;
        else                                          j.batchPartial++;
    }
    if (expectedBatch != 0) {
        // A declared request with no record at all is MISSING, which is a
        // different failure from a request that started but did not finish.
        for (u32 id = 1; id <= expectedBatch; id++) {
            bool seen = false;
            for (u32 k = 0; k < j.bizCount; k++) {
                if (j.biz[k].reqId == id) { seen = true; break; }
            }
            if (!seen) j.batchMissing++;
        }
        j.controlledBatchComplete =
            (j.batchComplete == expectedBatch &&
             j.batchMissing == 0 && j.batchPartial == 0 &&
             j.batchUnexpected == 0 && j.batchUnparsed == 0 &&
             j.bizCapped == 0 && j.holes == 0);
        j.batchWhy = j.controlledBatchComplete ? "complete"
                    : (j.batchMissing ? "requests-missing"
                    : (j.batchPartial ? "requests-incomplete"
                    : (j.batchUnexpected ? "requests-outside-the-declared-batch"
                    : (j.batchUnparsed ? "records-without-a-business-id"
                    : "degraded"))));
    } else {
        j.batchWhy = "batch-not-declared";
    }
}

// Convenience wrapper for callers that can afford the temporary. The host
// tests can (a test binary's stack is not the kernel's); the kext must use
// obsJoinInto() with a member.
static inline ObsJoin obsJoin(const u8 *blob, u64 bytes, u32 ringSize,
                              u64 winStart = 0, u64 winEnd = 0,
                              u32 expectedBatch = 0) {
    ObsJoin j;
    obsJoinInto(j, blob, bytes, ringSize, winStart, winEnd, expectedBatch);
    return j;
}

