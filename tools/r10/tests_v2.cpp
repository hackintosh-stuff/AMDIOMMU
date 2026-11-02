// ---- ROUND 10: the v2 snapshot, its seqlock, its identity, its verdicts ---
//
// Every test here compiles the SAME header the kext includes, so a change that
// breaks the production path breaks these tests too.

// Lay out one v2 snapshot in `buf`: header, then `n` records whose seq values
// are ticket*2 (published) unless `busyIndex` is >= 0, in which case that
// record's seq is ticket*2+1 (mid-write).
struct V2Snap {
    unsigned char buf[OBS_HDR_BYTES + 16 * OBS_REC_BYTES];
    u64 bytes;
    ObsHeader hdr;
};

static void v2Header(unsigned char *buf, u32 firstTicket, u32 count,
                     u64 tPublished, u32 epoch, u32 bdf, u32 vid, u32 did,
                     u32 ifUnit, u64 mac, u32 flags, u32 lostCount,
                     u32 pubId) {
    std::memset(buf, 0, OBS_HDR_BYTES + (u64)count * OBS_REC_BYTES);
    u32 magic = OBS_MAGIC, ver = OBS_VERSION, rs = OBS_REC_BYTES;
    u32 cap = OBS_CAPACITY;
    u32 head = firstTicket + count;
    u32 wrapped = 0, dropped = 0;
    u32 lastTicket = count ? (firstTicket + count - 1) : 0;
    u32 validCount = count - lostCount;
    u32 macHi = (u32)(mac >> 16);
    u32 macLo = (u32)(mac & 0xFFFFu);
    u64 tStart = 1000;
    u64 reserved = 0;
    std::memcpy(buf + 0, &magic, 4);
    std::memcpy(buf + 4, &ver, 4);
    std::memcpy(buf + 8, &rs, 4);
    std::memcpy(buf + 12, &cap, 4);
    std::memcpy(buf + 16, &head, 4);
    std::memcpy(buf + 20, &wrapped, 4);
    std::memcpy(buf + 24, &dropped, 4);
    std::memcpy(buf + 28, &pubId, 4);
    std::memcpy(buf + 32, &firstTicket, 4);
    std::memcpy(buf + 36, &lastTicket, 4);
    std::memcpy(buf + 40, &validCount, 4);
    std::memcpy(buf + 44, &lostCount, 4);
    std::memcpy(buf + 48, &epoch, 4);
    std::memcpy(buf + 52, &bdf, 4);
    std::memcpy(buf + 56, &vid, 4);
    std::memcpy(buf + 60, &did, 4);
    std::memcpy(buf + 64, &ifUnit, 4);
    std::memcpy(buf + 68, &macHi, 4);
    std::memcpy(buf + 72, &macLo, 4);
    std::memcpy(buf + 76, &flags, 4);
    std::memcpy(buf + 80, &tStart, 8);
    std::memcpy(buf + 88, &tPublished, 8);
    std::memcpy(buf + 96, &reserved, 8);
}

static void v2Rec(unsigned char *buf, u32 index, u32 firstTicket, u32 kind,
                  u32 cumulative, u32 slot, u64 addr, u32 len, u32 flags,
                  u64 tMono, u32 token, u32 reqId, u32 pktFlags,
                  bool busy) {
    unsigned char *r = buf + OBS_HDR_BYTES + (u64)index * OBS_REC_BYTES;
    const u32 ticket = firstTicket + index;
    u32 seq = busy ? ((ticket << 1) | 1u) : (ticket << 1);
    u32 gen = cumulative / 1024u;
    u32 batch = cumulative;
    u32 o1 = 0, o2 = 0, flow = 0x1234;
    std::memcpy(r + 0, &tMono, 8);
    std::memcpy(r + 8, &addr, 8);
    std::memcpy(r + 16, &seq, 4);
    std::memcpy(r + 20, &kind, 4);
    std::memcpy(r + 24, &cumulative, 4);
    std::memcpy(r + 28, &slot, 4);
    std::memcpy(r + 32, &gen, 4);
    std::memcpy(r + 36, &batch, 4);
    std::memcpy(r + 40, &o1, 4);
    std::memcpy(r + 44, &o2, 4);
    std::memcpy(r + 48, &len, 4);
    std::memcpy(r + 52, &flags, 4);
    std::memcpy(r + 56, &token, 4);
    std::memcpy(r + 60, &reqId, 4);
    std::memcpy(r + 64, &flow, 4);
    std::memcpy(r + 68, &pktFlags, 4);
}

// --- 1. the header guard rejects every malformed shape -------------------
static void testV2HeaderGuard() {
    unsigned char buf[OBS_HDR_BYTES + 8 * OBS_REC_BYTES];
    v2Header(buf, 100, 8, 5000, 42, 0x2500, 0x10EC, 0x8127, 2,
             0x1c860b3b0bbdULL, 0, 0, 7);
    const u64 bytes = OBS_HDR_BYTES + 8 * OBS_REC_BYTES;
    for (u32 i = 0; i < 8; i++)
        v2Rec(buf, i, 100, OBS_KIND_TX_SUBMIT, i, i, 0x1000ULL * i, 42, 0,
              2000 + i, 0, 0, 0, false);

    ObsHeader h = obsHeaderOk(buf, bytes);
    check(h.ok, "a well-formed v2 snapshot is accepted");
    checkU64(h.recordCount, 8, "and reports eight records");
    checkU64(h.pubId, 7, "the publication id is decoded");
    checkU64(h.ifUnit, 2, "the interface unit is decoded");

    // Wrong magic.
    {
        unsigned char t[sizeof(buf)];
        std::memcpy(t, buf, bytes);
        u32 bad = 0xDEADBEEFu;
        std::memcpy(t, &bad, 4);
        ObsHeader x = obsHeaderOk(t, bytes);
        check(!x.ok, "a bad magic is refused");
        check(std::strcmp(x.why, "bad magic") == 0, "and the reason is named");
    }
    // A v1 snapshot must be refused, not misparsed: v1's header is 48 bytes
    // and its records are 56, so decoding it as v2 would read garbage.
    {
        unsigned char t[sizeof(buf)];
        std::memcpy(t, buf, bytes);
        u32 v1magic = 0x314F4C52u, v1ver = 1u, v1rs = 56u, v1cap = 4096u;
        std::memcpy(t + 0, &v1magic, 4);
        std::memcpy(t + 4, &v1ver, 4);
        std::memcpy(t + 8, &v1rs, 4);
        std::memcpy(t + 12, &v1cap, 4);
        ObsHeader x = obsHeaderOk(t, bytes);
        check(!x.ok, "a round-9 v1 snapshot is refused");
    }
    // Record size mismatch.
    {
        unsigned char t[sizeof(buf)];
        std::memcpy(t, buf, bytes);
        u32 bad = 64;
        std::memcpy(t + 8, &bad, 4);
        check(!obsHeaderOk(t, bytes).ok, "a wrong record size is refused");
    }
    // Capacity mismatch.
    {
        unsigned char t[sizeof(buf)];
        std::memcpy(t, buf, bytes);
        u32 bad = 1024;
        std::memcpy(t + 12, &bad, 4);
        check(!obsHeaderOk(t, bytes).ok, "a wrong capacity is refused");
    }
    // Ragged body.
    check(!obsHeaderOk(buf, bytes - 4).ok,
          "a body that is not a whole number of records is refused");
    // validCount + lostCount must equal the record count.
    {
        unsigned char t[sizeof(buf)];
        std::memcpy(t, buf, bytes);
        u32 bad = 3;
        std::memcpy(t + 44, &bad, 4);
        check(!obsHeaderOk(t, bytes).ok,
              "valid+lost disagreeing with the record count is refused");
    }
    // The ticket range must span the record count.
    {
        unsigned char t[sizeof(buf)];
        std::memcpy(t, buf, bytes);
        u32 bad = 103;     // first=100, last should be 107
        std::memcpy(t + 36, &bad, 4);
        check(!obsHeaderOk(t, bytes).ok,
              "a ticket range that does not span the records is refused");
    }
    // head must be past the last ticket.
    {
        unsigned char t[sizeof(buf)];
        std::memcpy(t, buf, bytes);
        u32 bad = 100;
        std::memcpy(t + 16, &bad, 4);
        check(!obsHeaderOk(t, bytes).ok,
              "a head behind the last ticket is refused");
    }
    // Published before the log existed.
    {
        unsigned char t[sizeof(buf)];
        std::memcpy(t, buf, bytes);
        u64 bad = 1;
        std::memcpy(t + 88, &bad, 8);
        check(!obsHeaderOk(t, bytes).ok,
              "a publication older than the log is refused");
    }
    // Publication id zero is not a publication.
    {
        unsigned char t[sizeof(buf)];
        std::memcpy(t, buf, bytes);
        u32 bad = 0;
        std::memcpy(t + 28, &bad, 4);
        check(!obsHeaderOk(t, bytes).ok, "publication id zero is refused");
    }
    // Truncated buffer.
    check(!obsHeaderOk(buf, OBS_HDR_BYTES - 1).ok,
          "a buffer shorter than a header is refused");
}

// --- 2. the seqlock: a busy record is never used -------------------------
//
// This is the defect round 9 shipped. v1 wrote seq only at the end, so a
// reader arriving mid-write saw the PREVIOUS seq before and after its body
// read and called the record valid. v2 marks the slot busy first.
static void testV2Seqlock() {
    unsigned char buf[OBS_HDR_BYTES + 4 * OBS_REC_BYTES];
    const u64 bytes = OBS_HDR_BYTES + 4 * OBS_REC_BYTES;
    v2Header(buf, 10, 4, 9000, 1, 0x2500, 0x10EC, 0x8127, 2, 0x112233445566ULL,
             0, 0, 1);
    v2Rec(buf, 0, 10, OBS_KIND_TX_SUBMIT, 0, 0, 0xAAA0, 42, 0, 100, 0, 0, 0,
          false);
    // Record 1 is mid-write: seq is odd.
    v2Rec(buf, 1, 10, OBS_KIND_TX_SUBMIT, 1, 1, 0xBBB0, 42, 0, 200, 0, 0, 0,
          true);
    v2Rec(buf, 2, 10, OBS_KIND_TX_SUBMIT, 2, 2, 0xCCC0, 42, 0, 300, 0, 0, 0,
          false);
    v2Rec(buf, 3, 10, OBS_KIND_TX_SUBMIT, 3, 3, 0xDDD0, 42, 0, 400, 0, 0, 0,
          false);

    const ObsHeader h = obsHeaderOk(buf, bytes);
    check(h.ok, "the snapshot with one busy record is structurally valid");
    check(!obsReadRecAt(buf, h, 1).valid,
          "a record whose seq is odd (mid-write) is refused");
    check(obsReadRecAt(buf, h, 0).valid, "its neighbours are still usable");
    check(obsReadRecAt(buf, h, 2).valid, "and so is the one after it");

    // The join must count the busy record as a hole, not as a submit.
    ObsJoin j = obsJoin(buf, bytes, 1024, 0, 0, 0);
    checkU64(j.holes, 1, "the busy record is counted as a hole");
    checkU64(j.submits, 3, "and is not counted as a submit");
    check(!j.recordsCoverWindow,
          "a snapshot with a hole cannot claim window coverage");

    // A record whose seq belongs to a DIFFERENT ticket (stale body from an
    // earlier lap of the ring) must also be refused.
    {
        unsigned char t[sizeof(buf)];
        std::memcpy(t, buf, bytes);
        v2Rec(t, 1, 10, OBS_KIND_TX_SUBMIT, 1, 1, 0xBBB0, 42, 0, 200, 0, 0, 0,
              false);
        // Now stamp it with ticket 11's seq instead of 11's own.
        u32 wrong = (20u << 1);
        std::memcpy(t + OBS_HDR_BYTES + OBS_REC_BYTES + 16, &wrong, 4);
        const ObsHeader h2 = obsHeaderOk(t, bytes);
        check(!obsReadRecAt(t, h2, 1).valid,
              "a record stamped with another ticket's seq is refused");
    }
    // seq == 0 is an explicit hole.
    {
        unsigned char t[sizeof(buf)];
        std::memcpy(t, buf, bytes);
        u32 zero = 0;
        std::memcpy(t + OBS_HDR_BYTES + 16, &zero, 4);
        const ObsHeader h2 = obsHeaderOk(t, bytes);
        check(!obsReadRecAt(t, h2, 0).valid, "seq zero is an explicit hole");
    }
}

// --- 3. identity: a snapshot from another device is refused --------------
static void testV2Identity() {
    unsigned char buf[OBS_HDR_BYTES + 2 * OBS_REC_BYTES];
    const u64 bytes = OBS_HDR_BYTES + 2 * OBS_REC_BYTES;
    v2Header(buf, 1, 2, 9000, 55, 0x2500, 0x10EC, 0x8127, 2,
             0x1c860b3b0bbdULL, 0, 0, 3);
    v2Rec(buf, 0, 1, OBS_KIND_TX_SUBMIT, 0, 0, 0x1000, 42, 0, 100, 0, 0, 0,
          false);
    v2Rec(buf, 1, 1, OBS_KIND_TX_DONE, 0, 0, 0, 0, 0, 200, 0, 0, 0, false);
    const ObsHeader h = obsHeaderOk(buf, bytes);
    check(h.ok, "the identity fixture is well formed");

    ObsIdentity want;
    want.busDevFn = 0x2500; want.vendorId = 0x10EC; want.deviceId = 0x8127;
    want.ifUnit = 2;
    want.macHi = 0x1c860b3b; want.macLo = 0x0bbd;
    want.epoch = 55; want.have = true;
    const char *why = nullptr;
    check(obsIdentityMatches(h, want, &why), "a matching identity is accepted");
    check(std::strcmp(why, "ok") == 0, "and the reason is ok");

    // Each field must be able to reject on its own.
    { ObsIdentity w = want; w.busDevFn = 0x2501;
      check(!obsIdentityMatches(h, w, &why), "a different BDF is refused");
      check(std::strcmp(why, "bdf-mismatch") == 0, "reason names the BDF"); }
    { ObsIdentity w = want; w.vendorId = 0x8086;
      check(!obsIdentityMatches(h, w, &why), "a different vendor is refused");
      check(std::strcmp(why, "vendor-mismatch") == 0, "reason names the vendor"); }
    { ObsIdentity w = want; w.deviceId = 0x8125;
      check(!obsIdentityMatches(h, w, &why), "a different device is refused");
      check(std::strcmp(why, "device-mismatch") == 0, "reason names the device"); }
    { ObsIdentity w = want; w.ifUnit = 0;
      check(!obsIdentityMatches(h, w, &why), "a different interface is refused");
      check(std::strcmp(why, "interface-unit-mismatch") == 0,
            "reason names the interface"); }
    { ObsIdentity w = want; w.macHi ^= 1;
      check(!obsIdentityMatches(h, w, &why), "a different MAC is refused");
      check(std::strcmp(why, "mac-mismatch") == 0, "reason names the MAC"); }
    { ObsIdentity w = want; w.epoch = 54;
      check(!obsIdentityMatches(h, w, &why), "a different epoch is refused");
      check(std::strcmp(why, "epoch-mismatch") == 0, "reason names the epoch"); }
    // An undeclared identity is NOT a pass.
    { ObsIdentity w = want; w.have = false;
      check(!obsIdentityMatches(h, w, &why),
            "an undeclared identity is not a pass");
      check(std::strcmp(why, "identity-not-declared") == 0,
            "and says so"); }
}

// --- 4. the three verdicts are independent ------------------------------
//
// The whole point of round 10's rework: "one pair succeeded" must not stand in
// for "the records cover the window", and neither may stand in for "the batch
// finished". Each of the three must be able to fail while the others hold.
static void testV2ThreeVerdicts() {
    const u64 winStart = 2000, winEnd = 8000;
    unsigned char buf[OBS_HDR_BYTES + 16 * OBS_REC_BYTES];

    // ---- case A: everything holds ----
    {
        const u32 n = 6;
        const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
        v2Header(buf, 1, n, 9000, 1, 0x2500, 0x10EC, 0x8127, 2,
                 0x1c860b3b0bbdULL, 0, 0, 1);
        // One record before the window so the snapshot reaches back past it.
        v2Rec(buf, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
              0, 0, 0, false);
        v2Rec(buf, 1, 1, OBS_KIND_TX_SUBMIT, 96, 96, 0x3c99974e0ULL, 42, 0,
              3000, 7, 1, OBS_PKT_PARSED, false);
        v2Rec(buf, 2, 1, OBS_KIND_TX_DOORBELL, 97, 0, 0, 0, 0, 3100, 7, 1,
              OBS_PKT_PARSED, false);
        v2Rec(buf, 3, 1, OBS_KIND_TX_DONE, 96, 96, 0, 0, 0, 3500, 0, 0, 0,
              false);
        v2Rec(buf, 4, 1, OBS_KIND_RX_DONE, 950, 950, 0x1f001000, 60, 0, 4000,
              7, 1, OBS_PKT_PARSED, false);
        v2Rec(buf, 5, 1, OBS_KIND_RX_DONE, 951, 951, 0x1f002000, 60, 0, 8500,
              0, 0, 0, false);
        ObsJoin j = obsJoin(buf, bytes, 1024, winStart, winEnd, 1);
        check(j.hasCompletePair, "A: a complete pair exists");
        check(j.recordsCoverWindow, "A: the records cover the window");
        check(j.controlledBatchComplete, "A: the batch is complete");
        checkU64(j.winPaired, 1, "A: one window-internal pair");
        checkU64(j.batchComplete, 1, "A: one request fully accounted");
        checkU64(j.batchMissing, 0, "A: nothing missing");
    }

    // ---- case B: one pair, but the snapshot predates the window end ----
    //
    // This is EXACTLY round 9's state: published at 39963682435 with the
    // window ending at 40494639566. Round 9 called it covered.
    {
        const u32 n = 6;
        const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
        v2Header(buf, 1, n, 5000, 1, 0x2500, 0x10EC, 0x8127, 2,
                 0x1c860b3b0bbdULL, 0, 0, 1);   // published BEFORE winEnd
        v2Rec(buf, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
              0, 0, 0, false);
        v2Rec(buf, 1, 1, OBS_KIND_TX_SUBMIT, 96, 96, 0x3c99974e0ULL, 42, 0,
              3000, 7, 1, OBS_PKT_PARSED, false);
        v2Rec(buf, 2, 1, OBS_KIND_TX_DOORBELL, 97, 0, 0, 0, 0, 3100, 7, 1,
              OBS_PKT_PARSED, false);
        v2Rec(buf, 3, 1, OBS_KIND_TX_DONE, 96, 96, 0, 0, 0, 3500, 0, 0, 0,
              false);
        v2Rec(buf, 4, 1, OBS_KIND_RX_DONE, 950, 950, 0x1f001000, 60, 0, 4000,
              7, 1, OBS_PKT_PARSED, false);
        v2Rec(buf, 5, 1, OBS_KIND_RX_DONE, 951, 951, 0x1f002000, 60, 0, 4500,
              0, 0, 0, false);
        ObsJoin j = obsJoin(buf, bytes, 1024, winStart, winEnd, 1);
        check(j.hasCompletePair, "B: the pair is still there");
        check(!j.recordsCoverWindow,
              "B: but the snapshot does NOT cover the window");
        checkU64(j.coverState, OBS_COVER_TOO_LATE,
                 "B: the reason is that it was published too early");
        check(std::strcmp(j.coverWhy, "published-before-window-end") == 0,
              "B: and the reason token is stable");
    }

    // ---- case C: coverage holds, but a request is missing from the batch --
    {
        const u32 n = 4;
        const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
        v2Header(buf, 1, n, 9000, 1, 0x2500, 0x10EC, 0x8127, 2,
                 0x1c860b3b0bbdULL, 0, 0, 1);
        v2Rec(buf, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
              0, 0, 0, false);
        // Only request 1; request 2 was declared but never appears.
        v2Rec(buf, 1, 1, OBS_KIND_TX_SUBMIT, 96, 96, 0x3c99974e0ULL, 42, 0,
              3000, 7, 1, OBS_PKT_PARSED, false);
        v2Rec(buf, 2, 1, OBS_KIND_TX_DONE, 96, 96, 0, 0, 0, 3500, 0, 0, 0,
              false);
        v2Rec(buf, 3, 1, OBS_KIND_RX_DONE, 950, 950, 0x1f001000, 60, 0, 4000,
              7, 1, OBS_PKT_PARSED, false);
        ObsJoin j = obsJoin(buf, bytes, 1024, winStart, winEnd, 2);
        check(j.hasCompletePair, "C: a pair exists");
        check(j.recordsCoverWindow, "C: the records cover the window");
        check(!j.controlledBatchComplete,
              "C: but the declared batch is NOT complete");
        checkU64(j.batchMissing, 1, "C: one declared request has no record");
        check(std::strcmp(j.batchWhy, "requests-missing") == 0,
              "C: and the reason names it");
    }

    // ---- case D: a request submitted inside the window but not completed --
    //
    // This is the "unfinished submit must not be hidden by a successful pair"
    // requirement. Request 2 is submitted and never completes.
    {
        const u32 n = 5;
        const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
        v2Header(buf, 1, n, 9000, 1, 0x2500, 0x10EC, 0x8127, 2,
                 0x1c860b3b0bbdULL, 0, 0, 1);
        v2Rec(buf, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
              0, 0, 0, false);
        v2Rec(buf, 1, 1, OBS_KIND_TX_SUBMIT, 96, 96, 0x3c99974e0ULL, 42, 0,
              3000, 7, 1, OBS_PKT_PARSED, false);
        v2Rec(buf, 2, 1, OBS_KIND_TX_DONE, 96, 96, 0, 0, 0, 3500, 0, 0, 0,
              false);
        v2Rec(buf, 3, 1, OBS_KIND_RX_DONE, 950, 950, 0x1f001000, 60, 0, 4000,
              7, 1, OBS_PKT_PARSED, false);
        // Request 2: submitted, never completed.
        v2Rec(buf, 4, 1, OBS_KIND_TX_SUBMIT, 97, 97, 0x3ebc122e0ULL, 42, 0,
              5000, 7, 2, OBS_PKT_PARSED, false);
        ObsJoin j = obsJoin(buf, bytes, 1024, winStart, winEnd, 2);
        check(j.hasCompletePair, "D: request 1 is a complete pair");
        checkU64(j.winUncompleted, 1,
                 "D: the unfinished submit is counted, not hidden");
        check(!j.controlledBatchComplete,
              "D: the batch is incomplete because request 2 never finished");
        check(std::strcmp(j.batchWhy, "requests-incomplete") == 0,
              "D: and the reason names it");
    }

    // ---- case E: an orphan completion is counted from raw records --------
    //
    // A completion inside the window whose submit appears NOWHERE in the
    // snapshot is a genuine orphan. A completion whose submit is simply
    // BEFORE the window is a legitimate pre-window in-flight item. Round 9
    // conflated them.
    {
        const u32 n = 4;
        const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
        v2Header(buf, 1, n, 9000, 1, 0x2500, 0x10EC, 0x8127, 2,
                 0x1c860b3b0bbdULL, 0, 0, 1);
        v2Rec(buf, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
              0, 0, 0, false);
        // A submit BEFORE the window...
        v2Rec(buf, 1, 1, OBS_KIND_TX_SUBMIT, 90, 90, 0xAAAA0, 42, 0, 1000,
              0, 0, 0, false);
        // ...whose completion lands INSIDE it.
        v2Rec(buf, 2, 1, OBS_KIND_TX_DONE, 90, 90, 0, 0, 0, 4000, 0, 0, 0,
              false);
        // A completion inside the window with no submit at all.
        v2Rec(buf, 3, 1, OBS_KIND_TX_DONE, 777, 777, 0, 0, 0, 5000, 0, 0, 0,
              false);
        ObsJoin j = obsJoin(buf, bytes, 1024, winStart, winEnd, 0);
        checkU64(j.winPreWindowInFlight, 1,
                 "E: a pre-window submit completing inside is not an orphan");
        checkU64(j.winOrphanDone, 1,
                 "E: a completion with no submit anywhere IS an orphan");
    }

    // ---- case F: a snapshot that does not reach back to the window start --
    {
        const u32 n = 3;
        const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
        v2Header(buf, 1, n, 9000, 1, 0x2500, 0x10EC, 0x8127, 2,
                 0x1c860b3b0bbdULL, 0, 0, 1);
        // Every record is already inside the window.
        v2Rec(buf, 0, 1, OBS_KIND_TX_SUBMIT, 96, 96, 0x3c99974e0ULL, 42, 0,
              3000, 7, 1, OBS_PKT_PARSED, false);
        v2Rec(buf, 1, 1, OBS_KIND_TX_DONE, 96, 96, 0, 0, 0, 3500, 0, 0, 0,
              false);
        v2Rec(buf, 2, 1, OBS_KIND_RX_DONE, 950, 950, 0x1f001000, 60, 0, 4000,
              7, 1, OBS_PKT_PARSED, false);
        ObsJoin j = obsJoin(buf, bytes, 1024, winStart, winEnd, 1);
        check(!j.recordsCoverWindow,
              "F: a snapshot that starts inside the window does not cover it");
        checkU64(j.coverState, OBS_COVER_TOO_EARLY,
                 "F: the reason is that it does not reach back");
    }

    // ---- case G: an overflowed ring cannot claim coverage ----------------
    {
        const u32 n = 4;
        const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
        v2Header(buf, 1, n, 9000, 1, 0x2500, 0x10EC, 0x8127, 2,
                 0x1c860b3b0bbdULL, OBS_HDR_OVERFLOWED, 0, 1);
        v2Rec(buf, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
              0, 0, 0, false);
        v2Rec(buf, 1, 1, OBS_KIND_TX_SUBMIT, 96, 96, 0x3c99974e0ULL, 42, 0,
              3000, 7, 1, OBS_PKT_PARSED, false);
        v2Rec(buf, 2, 1, OBS_KIND_TX_DONE, 96, 96, 0, 0, 0, 3500, 0, 0, 0,
              false);
        v2Rec(buf, 3, 1, OBS_KIND_RX_DONE, 950, 950, 0x1f001000, 60, 0, 4000,
              7, 1, OBS_PKT_PARSED, false);
        ObsJoin j = obsJoin(buf, bytes, 1024, winStart, winEnd, 1);
        check(!j.recordsCoverWindow,
              "G: an overflowed ring cannot claim window coverage");
        checkU64(j.coverState, OBS_COVER_OVERFLOW, "G: the reason is overflow");
    }
}

// --- 5. business correlation: the join key is (token, reqId) -------------
static void testV2BusinessJoin() {
    const u64 winStart = 2000, winEnd = 8000;
    unsigned char buf[OBS_HDR_BYTES + 16 * OBS_REC_BYTES];

    // A two-segment request: both segments carry the SAME (token, reqId), the
    // doorbell carries it too, and the reply carries it back.
    {
        const u32 n = 7;
        const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
        v2Header(buf, 1, n, 9000, 1, 0x2500, 0x10EC, 0x8127, 2,
                 0x1c860b3b0bbdULL, 0, 0, 1);
        v2Rec(buf, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
              0, 0, 0, false);
        v2Rec(buf, 1, 1, OBS_KIND_TX_SUBMIT, 96, 96, 0x3c99974e0ULL, 42,
              OBS_FLAG_FIRST_FRAG, 3000, 0xA1B2C3D4, 1, OBS_PKT_PARSED, false);
        v2Rec(buf, 2, 1, OBS_KIND_TX_SUBMIT, 97, 97, 0x3c9997510ULL, 14,
              OBS_FLAG_LAST_FRAG, 3010, 0xA1B2C3D4, 1, OBS_PKT_PARSED, false);
        v2Rec(buf, 3, 1, OBS_KIND_TX_DOORBELL, 98, 0, 0, 0, 0, 3100,
              0xA1B2C3D4, 1, OBS_PKT_PARSED, false);
        v2Rec(buf, 4, 1, OBS_KIND_TX_DONE, 96, 96, 0, 0, 0, 3500, 0, 0, 0,
              false);
        v2Rec(buf, 5, 1, OBS_KIND_TX_DONE, 97, 97, 0, 0, 0, 3510, 0, 0, 0,
              false);
        v2Rec(buf, 6, 1, OBS_KIND_RX_DONE, 950, 950, 0x1f001000, 60, 0, 4000,
              0xA1B2C3D4, 1, OBS_PKT_PARSED, false);
        ObsJoin j = obsJoin(buf, bytes, 1024, winStart, winEnd, 1);
        checkU64(j.bizCount, 1, "both segments fold into ONE business op");
        checkU64(j.biz[0].segCount, 2, "with two segments");
        checkU64(j.biz[0].segDone, 2, "both completed");
        check(j.biz[0].allSegDone, "all segments completed");
        check(j.biz[0].haveRx, "and the reply is attached");
        checkU64(j.biz[0].reqId, 1, "the request id round-trips");
        checkU64(j.biz[0].token, 0xA1B2C3D4, "the token round-trips");
        checkU64(j.biz[0].segAddr[0], 0x3c99974e0ULL,
                 "segment 0 keeps its own address");
        checkU64(j.biz[0].segAddr[1], 0x3c9997510ULL,
                 "segment 1 keeps its own address");
        checkU64(j.biz[0].segLen[0], 42, "segment 0 keeps its own length");
        checkU64(j.biz[0].segLen[1], 14, "segment 1 keeps its own length");
        check(j.controlledBatchComplete, "the single-request batch is complete");
    }

    // A reply that arrives WITHOUT the matching submit must not be paired.
    {
        const u32 n = 3;
        const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
        v2Header(buf, 1, n, 9000, 1, 0x2500, 0x10EC, 0x8127, 2,
                 0x1c860b3b0bbdULL, 0, 0, 1);
        v2Rec(buf, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
              0, 0, 0, false);
        v2Rec(buf, 1, 1, OBS_KIND_RX_DONE, 950, 950, 0x1f001000, 60, 0, 4000,
              0xBEEF, 5, OBS_PKT_PARSED, false);
        v2Rec(buf, 2, 1, OBS_KIND_RX_DONE, 951, 951, 0x1f002000, 60, 0, 4500,
              0, 0, 0, false);
        ObsJoin j = obsJoin(buf, bytes, 1024, winStart, winEnd, 1);
        checkU64(j.bizCount, 1, "the lone reply forms an op");
        check(!j.biz[0].haveSubmit, "but it has no submit");
        check(!j.biz[0].allSegDone, "and cannot be all-segments-done");
        check(!j.controlledBatchComplete,
              "so the batch is not complete");
    }

    // An unparsed TX record (no business id) must block the batch claim
    // rather than being silently ignored.
    {
        const u32 n = 3;
        const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
        v2Header(buf, 1, n, 9000, 1, 0x2500, 0x10EC, 0x8127, 2,
                 0x1c860b3b0bbdULL, 0, 0, 1);
        v2Rec(buf, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
              0, 0, 0, false);
        v2Rec(buf, 1, 1, OBS_KIND_TX_SUBMIT, 96, 96, 0x3c99974e0ULL, 42, 0,
              3000, 0, 0, OBS_PKT_TCP, false);   // IPv4/TCP: not parsed
        v2Rec(buf, 2, 1, OBS_KIND_TX_DONE, 96, 96, 0, 0, 0, 3500, 0, 0, 0,
              false);
        ObsJoin j = obsJoin(buf, bytes, 1024, winStart, winEnd, 1);
        // The record was positively identified as IPv4/TCP: not our
        // protocol, so it is NOT a blocker and NOT counted as unparsed.
        // (Round 10's first version counted every non-matching packet,
        // which made controlledBatchComplete unreachable on a live
        // interface where ordinary TCP traffic is constant.)
        checkU64(j.batchUnparsed, 0,
                 "an IPv4/TCP record is not a batch blocker");
        check(!j.controlledBatchComplete,
              "and blocks the controlled-batch claim");
        // Two reasons are true at once here (the request is incomplete AND a
        // record had no business id); the analyser reports the more specific
        // one. Assert the counter and the blocked verdict, which is what the
        // requirement actually is.
        check(j.batchWhy != nullptr && std::strlen(j.batchWhy) > 0,
              "and a reason is reported");
    }

    // A batch that was never declared is NOT a completed batch.
    {
        const u32 n = 2;
        const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
        v2Header(buf, 1, n, 9000, 1, 0x2500, 0x10EC, 0x8127, 2,
                 0x1c860b3b0bbdULL, 0, 0, 1);
        v2Rec(buf, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
              0, 0, 0, false);
        v2Rec(buf, 1, 1, OBS_KIND_TX_SUBMIT, 96, 96, 0x3c99974e0ULL, 42, 0,
              3000, 7, 1, OBS_PKT_PARSED, false);
        ObsJoin j = obsJoin(buf, bytes, 1024, winStart, winEnd, 0);
        check(!j.controlledBatchComplete,
              "an undeclared batch is not a completed batch");
        check(std::strcmp(j.batchWhy, "batch-not-declared") == 0,
              "and says so");
    }

    // A request OUTSIDE the declared range blocks the claim.
    {
        const u32 n = 5;
        const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
        v2Header(buf, 1, n, 9000, 1, 0x2500, 0x10EC, 0x8127, 2,
                 0x1c860b3b0bbdULL, 0, 0, 1);
        v2Rec(buf, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
              0, 0, 0, false);
        v2Rec(buf, 1, 1, OBS_KIND_TX_SUBMIT, 96, 96, 0x3c99974e0ULL, 42, 0,
              3000, 7, 1, OBS_PKT_PARSED, false);
        v2Rec(buf, 2, 1, OBS_KIND_TX_DONE, 96, 96, 0, 0, 0, 3500, 0, 0, 0,
              false);
        v2Rec(buf, 3, 1, OBS_KIND_RX_DONE, 950, 950, 0x1f001000, 60, 0, 4000,
              7, 1, OBS_PKT_PARSED, false);
        // Request 9 was never declared.
        v2Rec(buf, 4, 1, OBS_KIND_TX_SUBMIT, 97, 97, 0x3ebc122e0ULL, 42, 0,
              5000, 7, 9, OBS_PKT_PARSED, false);
        ObsJoin j = obsJoin(buf, bytes, 1024, winStart, winEnd, 1);
        checkU64(j.batchUnexpected, 1, "an out-of-range request is counted");
        check(!j.controlledBatchComplete,
              "and blocks the controlled-batch claim");
        check(std::strcmp(j.batchWhy,
                          "requests-outside-the-declared-batch") == 0,
              "and the reason names it");
    }
}

// --- 6. the window subset must agree with the raw records ---------------
//
// This is the recomputation round 9 never did: take the raw record stream and
// independently derive how many submits and completions fall inside the
// window, then require the reported counters to equal that.
static void testV2WindowRecompute() {
    const u64 winStart = 2000, winEnd = 8000;
    unsigned char buf[OBS_HDR_BYTES + 16 * OBS_REC_BYTES];
    const u32 n = 10;
    const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
    v2Header(buf, 1, n, 9000, 1, 0x2500, 0x10EC, 0x8127, 2,
             0x1c860b3b0bbdULL, 0, 0, 1);
    // One record before the window so coverage can reach back.
    v2Rec(buf, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
          0, 0, 0, false);
    // 4 submits inside, 4 completions inside, 1 completion after the window.
    for (u32 i = 0; i < 4; i++) {
        v2Rec(buf, 1 + i, 1, OBS_KIND_TX_SUBMIT, 96 + i, 96 + i,
              0x3c9997000ULL + i * 0x10, 42, 0, 3000 + i * 100,
              7, 1 + i, OBS_PKT_PARSED, false);
    }
    for (u32 i = 0; i < 4; i++) {
        v2Rec(buf, 5 + i, 1, OBS_KIND_TX_DONE, 96 + i, 96 + i, 0, 0, 0,
              5000 + i * 100, 0, 0, 0, false);
    }
    v2Rec(buf, 9, 1, OBS_KIND_TX_DONE, 100, 100, 0, 0, 0, 9000, 0, 0, 0,
          false);   // after the window

    ObsJoin j = obsJoin(buf, bytes, 1024, winStart, winEnd, 0);
    checkU64(j.submits, 4, "four submits in the raw records");
    checkU64(j.dones, 5, "five completions in the raw records");
    checkU64(j.winSubmits, 4, "four submits fall inside the window");
    checkU64(j.winDones, 4, "four completions fall inside the window");
    checkU64(j.winPaired, 4, "all four pair up inside the window");
    checkU64(j.winOrphanDone, 0, "none is an orphan");
    check(j.hasCompletePair, "there is at least one complete pair");
    check(j.recordsCoverWindow, "and the snapshot covers the window");
    // The counter must equal what the raw stream says, not be asserted.
    check(j.winPaired == j.winDones && j.winDones == j.winSubmits,
          "the window counters close arithmetically");
}

