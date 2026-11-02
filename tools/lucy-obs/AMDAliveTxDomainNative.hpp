// Round17 evidence ABI: raw live-domain PTEs, real invalidation commands and
// per-generation native-segment records. Layout of Record is byte-identical to
// round16's (720 B); only the record count, version and the meaning of
// `segments[].pa` changed (real mbuf physical segment, not staging copy).
#pragma once
#include <stdint.h>
namespace r17domain {
static constexpr uint32_t kVersion = 3, kMaxRecords = 32;
struct Command {
    uint32_t d[4];
    uint64_t expected, observed, tComplete;
};
struct Segment { uint64_t pa, bytes, iova; };
struct Record {
    uint64_t handle, tMapPublish, tMapInv, tClearPublish, tRetireInv;
    uint32_t count, pages, token, req, status;
    /* maplen (was `reserved` before round 19): the exact length the mapper
     * returned for this mapping and that IOKit therefore hands back to
     * iovmUnmapMemory(). Equal to the frame length for a contiguous run;
     * strictly larger (page-aligned window minus the first in-page offset) for
     * a fragmented layout. Layout of Record is byte-identical to round 16/17;
     * older captures simply wrote 0 here. */
    uint32_t maplen;
    Segment segments[8];
    uint64_t physical[16], mapPte[16], clearPte[16];
    Command mapCommand, retireCommand;
};
struct Snapshot {
    uint32_t version, bytes, count, flags;
    uint64_t iovaBase, iovaBytes, rootPA, leafPA, ptBase, ptBytes;
    uint32_t rootLevel, devid, domid, active;
    Record records[kMaxRecords]; // completed history, index=absolute retirement sequence%32
    uint32_t historyTotal, historyStart, mapsTotal, retiresTotal;
    uint32_t commandCapacity, commandSubmits, commandCompleted, commandWraps;
    uint32_t commandPostWrapCompleted, liveOwners, slotsUsed, maxLiveOwners;
    uint32_t slotUses[4];
    uint64_t completionSequence;
};
// Separate scalar properties (not part of the fixed header):
//   m2-3b-submits            total invalidation submissions used
//   m2-3b-submit-budget      submissions allowed by the finite budget
//   m2-3b-map-accepted       Map calls answered with a live mapping
//   m2-3b-map-rejected       Map calls refused (budget/protocol/geometry)
//   m2-3b-retires            successful Retire calls
//   m2-3b-live-owner-max     high-water mark of simultaneously live owners
//   m2-3b-owners-held        live owners at export time (must be 0)
// Those are cross-checks; the authoritative owner bound is derived by the
// analyzer from the record timeline itself.
}
