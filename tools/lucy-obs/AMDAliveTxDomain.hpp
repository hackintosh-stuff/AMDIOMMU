// Round16 evidence ABI: raw live-domain PTEs and completed invalidation commands.
#pragma once
#include <stdint.h>
namespace r16domain {
static constexpr uint32_t kVersion=1, kMaxRecords=8;
struct Command {
    uint32_t d[4];
    uint64_t expected, observed, tComplete;
};
struct Segment { uint64_t pa, bytes, iova; };
struct Record {
    uint64_t handle, tMapPublish, tMapInv, tClearPublish, tRetireInv;
    uint32_t count, pages, token, req, status, reserved;
    Segment segments[8];
    uint64_t physical[16], mapPte[16], clearPte[16];
    Command mapCommand, retireCommand;
};
struct Snapshot {
    uint32_t version, bytes, count, flags;
    uint64_t iovaBase, iovaBytes, rootPA, leafPA, ptBase, ptBytes;
    uint32_t rootLevel, devid, domid, active;
    Record records[kMaxRecords];
};
}
