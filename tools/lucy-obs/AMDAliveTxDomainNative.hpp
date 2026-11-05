// Round32 domain evidence ABI4: independent allocation metadata, mapping-local
// PTEs and real invalidation commands. Record is 1304 B; Snapshot is 44592 B.
// Retired history and the two retained capacity-probe records never own pages.
#pragma once
#include <stdint.h>
namespace r17domain {
static constexpr uint32_t kVersion = 4, kMaxRecords = 32;
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
     * a fragmented layout. The field keeps its original prefix offset even
     * though ABI4 expands the remaining allocation evidence. */
    uint32_t maplen;
    // Round32: record index identifies metadata, basePage identifies the
    // separately allocated IOVA extent. PTE arrays are mapping-local.
    uint32_t basePage, recordIndex;
    Segment segments[16];
    uint64_t physical[32], mapPte[32], clearPte[32];
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
    uint32_t slotUses[16]; // activity per metadata record, not IOVA stripes
    uint64_t completionSequence;
    uint32_t livePages, peakPages, maxMappedPages, reusedAllocations;
    uint32_t probeMaps, probeUnmaps, probePeakOwners, probeMaxPages;
    uint32_t probePassed, probeReused;
    uint64_t probeStart, probeEnd;
    Record probeFirst, probeReuse;
};
// Separate scalar properties (not part of the fixed header):
//   m2-3b-submits            total invalidation submissions used
//   m2-3b-command-capacity   entries in the reusable hardware command ring
//   m2-3b-map-accepted       Map calls answered with a live mapping
//   m2-3b-map-rejected       Map calls refused (capacity/protocol/geometry)
//   m2-3b-retires            successful Retire calls
//   m2-3b-live-owner-max     high-water mark of simultaneously live owners
//   m2-3b-owners-held        live owners at export time (must be 0)
// Those are cross-checks; the authoritative owner bound is derived by the
// analyzer from the record timeline itself.
}
