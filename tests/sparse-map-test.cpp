// Focused round-15 tests: compile the production inactive-table updater.
#include <cassert>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include "../probe/amd_iommu_sparse_core.hpp"
#include "../probe/amd_iommu_bizwalk_core.hpp"
using amdsparse::u64;
static u64 mem[64 * 512];
static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { std::printf("FAIL line %u: %s\n", __LINE__, #x); return 1; } } while (0)
int main() {
    const u64 base = 0x100000ULL;
    amdsparse::Arena a = {mem, base, 64, 1, 4, base, 0, 0, nullptr};
    auto read = [&](u64 pa, unsigned ix) -> u64 {
        if (pa < base || pa - base >= sizeof(mem)) return 0;
        return mem[(pa-base)/8 + ix];
    };
    auto full = [&](u64 addr, u64 bytes) -> bool {
        amdbw::RangeResult r;
        amdbw::walkRange(read, 4, base, addr, bytes, true, r);
        return r.ok;
    };
    // Real high fault lead and a full writable page, not received packet size.
    CHECK(amdsparse::mapOwnedRange(a, 0x4040d2000ULL, 4096));
    CHECK(full(0x4040d2000ULL, 4096));
    CHECK(!full(0x4040d1000ULL, 4096));
    CHECK(!full(0x4040d3000ULL, 4096));
    unsigned used = a.next;
    CHECK(amdsparse::mapOwnedRange(a, 0x4040d2000ULL, 4096));
    CHECK(a.next == used);
    // Unaligned full capacity crosses pages, 2MiB and 1GiB boundaries.
    for (u64 addr : {0x43fffff80ULL, 0x47fffff80ULL, 0x8000001fff80ULL}) {
        CHECK(amdsparse::mapOwnedRange(a, addr, 4096));
        CHECK(full(addr, 4096));
        CHECK(!full(addr, 8193));
    }
    CHECK(!amdsparse::mapOwnedRange(a, 0, 4096));
    CHECK(!amdsparse::mapOwnedRange(a, 0x4040d2000ULL, 0));
    CHECK(!amdsparse::mapOwnedRange(a, 0xfffffffffffff000ULL, 8192));
    CHECK(!amdsparse::mapOwnedRange(a, 1ULL<<48, 4096));
    // Existing bootstrap large leaf reused, never enlarged into a high hole.
    std::memset(mem, 0, sizeof(mem));
    a = {mem, base, 64, 3, 4, base, 0, 0, nullptr};
    const u64 rw = amdpte::PTE_IR | amdpte::PTE_IW;
    mem[0] = amdpte::makeTablePde(3, base+4096, rw);
    mem[512] = amdpte::makeTablePde(2, base+8192, rw);
    mem[1024] = amdpte::makeDefaultLeaf(2, 0, rw);
    CHECK(amdsparse::mapOwnedRange(a, 4096, 4096));
    CHECK(a.next == 3 && a.addedLeaves == 0);
    mem[1024] &= ~amdpte::PTE_IW;
    CHECK(!amdsparse::mapOwnedRange(a, 4096, 4096));
    mem[1024] = amdpte::makeDefaultLeaf(2, 0x200000, rw);
    CHECK(!amdsparse::mapOwnedRange(a, 4096, 4096));
    // Budget failure is explicit; caller MUST discard inactive table on error.
    std::memset(mem, 0, sizeof(mem));
    a = {mem, base, 2, 1, 4, base, 0, 0, nullptr};
    CHECK(!amdsparse::mapOwnedRange(a, 0x4040d2000ULL, 4096));
    CHECK(std::strcmp(a.why, "sparse-table-page-budget") == 0);
    CHECK(a.next <= a.pages);
    // Parent pointers may only reference the driver's/probe's own arena.
    mem[0] = amdpte::makeTablePde(3, base + sizeof(mem), rw);
    a = {mem, base, 64, 1, 4, base, 0, 0, nullptr};
    CHECK(!amdsparse::mapOwnedRange(a, 4096, 4096));
    CHECK(std::strcmp(a.why, "table-outside-owned-arena") == 0);
    std::printf("RESULT: SPARSE OWNED MAP OK (%u checks)\n", checks);
    return 0;
}
