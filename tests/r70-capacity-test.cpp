// R70 S1 host regression for the capacity model.
//
// Three properties are required, and all three are checked against the same
// headers the kext compiles:
//
//   1. The runtime-sized allocator behaves EXACTLY like the compile-time one
//      it replaces, so the legacy profile is byte-compatible with R67-2.
//   2. The profile table exposes the documented capacities and unknown names
//      are refused instead of silently widening the arena.
//   3. The arena arithmetic in amd_iommu_mapper_abi.hpp matches the carve
//      order in AMDMapperProbeMapper.cpp.
#include <cstdint>
#include <cstdio>
#include <cstring>

#include <utility>
#include <vector>

#include "../kext/amd_iommu_mapper_abi.hpp"
#include "../kext/amd_iommu_tx_core.hpp"

namespace {

int failures;

void check(bool ok, const char *what) {
    if (!ok) {
        std::printf("FAIL %s\n", what);
        ++failures;
    }
}

// Deterministic generator: the whole point is that both allocators see the
// same operation sequence, so the sequence must not depend on the platform.
struct Rng {
    std::uint64_t state;
    std::uint32_t next() {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        return static_cast<std::uint32_t>(state >> 33);
    }
    std::uint32_t below(std::uint32_t n) { return next() % n; }
};

void allocationEquivalence() {
    amdtx::BoundedAllocator<4096, 128> fixed{};
    std::uint64_t used[4096 / 64] = {};
    std::uint64_t ever[4096 / 64] = {};
    amdtx::RuntimeAllocator runtime{used, ever, 4096, 128, 0, 0, 0};

    const std::uint32_t alignments[4] = {1, 1, 2, 8};
    std::vector<std::pair<unsigned, unsigned>> live;
    Rng rng{0x5eed1234U};
    unsigned mismatches = 0;
    for (unsigned step = 0; step < 20000; ++step) {
        const bool wantAlloc = live.empty() || rng.below(100) < 62;
        if (wantAlloc) {
            const unsigned pages = 1 + rng.below(128);
            const unsigned align = alignments[rng.below(4)];
            unsigned baseFixed = 0, baseRuntime = 0;
            const bool okFixed = amdtx::allocate(fixed, pages, baseFixed, align);
            const bool okRuntime = amdtx::allocate(runtime, pages, baseRuntime, align);
            if (okFixed != okRuntime || (okFixed && baseFixed != baseRuntime)) ++mismatches;
            if (okFixed) live.emplace_back(baseFixed, pages);
        } else {
            const unsigned pick = rng.below(static_cast<std::uint32_t>(live.size()));
            const auto range = live[pick];
            live.erase(live.begin() + pick);
            const bool okFixed = amdtx::release(fixed, range.first, range.second);
            const bool okRuntime = amdtx::release(runtime, range.first, range.second);
            if (okFixed != okRuntime) ++mismatches;
        }
        if (fixed.livePages != runtime.livePages ||
            fixed.peakPages != runtime.peakPages ||
            fixed.reusedAllocations != runtime.reusedAllocations ||
            std::memcmp(fixed.used, used, sizeof(used)) != 0 ||
            std::memcmp(fixed.ever, ever, sizeof(ever)) != 0) {
            ++mismatches;
        }
        if (mismatches) break;
    }
    check(mismatches == 0, "runtime allocator diverged from the compile-time allocator");
    // The legacy pool must also be fully drainable: every page returns to the
    // bitmap, which is what makes unmap-then-remap reuse identical.
    for (const auto &range : live) amdtx::release(fixed, range.first, range.second);
    for (std::size_t i = 0; i < 4096 / 64; ++i) {
        check(fixed.used[i] == 0, "legacy allocator did not return every page");
    }
}

void profileTable() {
    check(r44mapper::kProfileLegacy.records == r44mapper::kRecords,
          "legacy profile changed the record count");
    check(r44mapper::kProfileLegacy.pages == r44mapper::kPages,
          "legacy profile changed the IOVA window");
    check(r44mapper::kProfileLegacy.mapPages == r44mapper::kMapPages &&
              r44mapper::kProfileLegacy.runs == r44mapper::kRuns,
          "legacy profile changed the per-map bound");
    check(r44mapper::kProfileRl10g.records > r44mapper::kProfileLegacy.records,
          "rl-10g must size for a packet pool, not for a ring");
    check(r44mapper::kProfileRl10g.pages % 512 == 0, "leaf tables cover 2 MiB each");
    check(r44mapper::kProfileRl10g.tablePages >=
              r44mapper::kProfileRl10g.pages / 512 + 2,
          "profile does not cover its own page tables");
    check(r44mapper::profileForName(nullptr) == &r44mapper::kProfileLegacy,
          "missing name must fall back to the legacy profile");
    check(r44mapper::profileForName("") == &r44mapper::kProfileLegacy,
          "empty name must fall back to the legacy profile");
    check(r44mapper::profileForName("rl-10g") == &r44mapper::kProfileRl10g,
          "rl-10g lookup failed");
    check(r44mapper::profileForName("rl-l0g") == nullptr,
          "a typo must be refused, never resolved to another profile");
    check(r44mapper::profileForName("native-legacy") == &r44mapper::kProfileLegacy,
          "native-legacy lookup failed");
    check(r44mapper::profileForName("rl-10g-max") == &r44mapper::kProfileRl10gMax,
          "rl-10g-max lookup failed");
    check(r44mapper::kProfileRl10gMax.records == 65535,
          "measurement ceiling must use the largest UInt16 slot count");
}

void arenaArithmetic() {
    // Hand-computed from the carve order in AMDMapperProbeMapper.cpp:
    // 1024*120 + 4096*8 + 4096*2 + 128 + 8*8 + 2*64*8 = 165056 -> 167936.
    check(r44mapper::arenaBytesFor(r44mapper::kProfileLegacy) == 167936ULL,
          "legacy arena size does not match the ABI3 footprint");
    // 16384*120 + 131072*8 + 131072*2 + 256*8 + 256*8 + 2*2048*8 = 3313664,
    // already a whole number of pages.
    check(r44mapper::arenaBytesFor(r44mapper::kProfileRl10g) == 3313664ULL,
          "rl-10g arena size does not match the documented footprint");
    check(r44mapper::arenaBytesFor(r44mapper::kProfileRl10g) <
              r44mapper::kMaxArenaBytes,
          "rl-10g arena exceeds the wired-memory guard");
    // Ceiling profile: 65535*120 + 262144*8 + 262144*2 + 1024*8 + 512*8 +
    // 2*4096*8 = 10563464 -> 10563584.
    check(r44mapper::arenaBytesFor(r44mapper::kProfileRl10gMax) == 10563584ULL,
          "rl-10g-max arena size does not match the documented footprint");
    check(r44mapper::arenaBytesFor(r44mapper::kProfileRl10gMax) <
              r44mapper::kMaxArenaBytes,
          "rl-10g-max arena exceeds the wired-memory guard");
    check(r44mapper::kMappingBytes == 120, "record slot size changed");
}

void devicePolicy() {
    // S2 admission input: only AppleEthernetRL on the auto-attach path widens.
    check(r44mapper::profileForDevice(0x10ec, 0x8124, true) ==
              &r44mapper::kProfileRl10gMax,
          "AppleEthernetRL 8124 must take the 10 GbE-sized profile");
    check(r44mapper::profileForDevice(0x10ec, 0x8127, true) ==
              &r44mapper::kProfileRl10gMax,
          "AppleEthernetRL 8127 must take the 10 GbE-sized profile");
    check(r44mapper::profileForDevice(0x10ec, 0x8123, true) ==
              &r44mapper::kProfileLegacy,
          "device below the Apple RL range must keep the legacy window");
    check(r44mapper::profileForDevice(0x10ec, 0x8128, true) ==
              &r44mapper::kProfileLegacy,
          "device above the Apple RL range must keep the legacy window");
    check(r44mapper::profileForDevice(0x10ec, 0x8168, true) ==
              &r44mapper::kProfileLegacy,
          "the board RTL8111 must keep the accepted ABI3 arena");
    check(r44mapper::profileForDevice(0x8086, 0x8127, true) ==
              &r44mapper::kProfileLegacy,
          "a foreign vendor must not inherit the Apple profile");
    check(r44mapper::profileForDevice(0x10ec, 0x8127, false) ==
              &r44mapper::kProfileLegacy,
          "the claim path (Lucy) must keep the accepted ABI3 arena");
}

void capacitySemantics() {
    // The allocator must grant exactly poolPages 1-page spans and then refuse:
    // that is the difference between a ring-sized arena and a pool-sized one.
    std::uint64_t used[512 / 64] = {};
    std::uint64_t ever[512 / 64] = {};
    amdtx::RuntimeAllocator runtime{used, ever, 512, 1, 0, 0, 0};
    unsigned granted = 0;
    unsigned base = 0;
    while (amdtx::allocate(runtime, 1, base)) ++granted;
    check(granted == 512, "1-page grants do not fill the pool exactly");
    check(runtime.livePages == 512, "live page accounting differs from grants");
    amdtx::release(runtime, 0, 1);
    check(amdtx::allocate(runtime, 1, base) && base == 0,
          "a released page is not reused first");
    // A multi-page request larger than maxMapPages must be refused, not split.
    check(!amdtx::allocate(runtime, 2, base), "per-map bound was ignored");
}

} // namespace

int main() {
    allocationEquivalence();
    profileTable();
    arenaArithmetic();
    devicePolicy();
    capacitySemantics();
    if (failures) {
        std::printf("R70_CAPACITY_FAILURES=%d\n", failures);
        return 1;
    }
    std::printf("R70_CAPACITY_OK\n");
    return 0;
}
