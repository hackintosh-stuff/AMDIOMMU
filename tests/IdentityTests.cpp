#include "amd_iommu/IdentityMap.hpp"
#include <stdio.h>
#include <stdint.h>

using namespace amd_iommu;
int runIvrsTests();
int runTopologyTests();
static unsigned checks = 0, failures = 0;
#define CHECK(x) do { ++checks; if (!(x)) { ++failures; \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); } } while (0)

struct Fixture { const PhysicalRun *runs; unsigned count; unsigned calls; };
static bool readRun(void *context, uint64_t offset, PhysicalRun *out) {
    auto &f = *static_cast<Fixture *>(context);
    ++f.calls;
    for (unsigned i = 0; i < f.count; ++i) {
        if (offset < f.runs[i].length) {
            *out = {f.runs[i].address + offset, f.runs[i].length - offset};
            return true;
        }
        offset -= f.runs[i].length;
    }
    return false;
}
static bool zeroRun(void *, uint64_t, PhysicalRun *out) {
    *out = {0x1000, 0}; return true;
}
static bool byteRun(void *, uint64_t offset, PhysicalRun *out) {
    *out = {0x1000 + offset, 1}; return true;
}
static bool topRun(void *, uint64_t, PhysicalRun *out) {
    *out = {~uint64_t(0), ~uint64_t(0)}; return true;
}
static void expect(IdentityRequest r, const PhysicalRun *runs, unsigned n,
                   IdentityStatus expected, uint64_t address = 0) {
    Fixture f{runs, n, 0};
    IdentityResult out{99, 99, 99};
    const auto status = validateIdentity(r, readRun, &f, out);
    CHECK(status == expected);
    CHECK(out.segmentsRead == f.calls);
    CHECK(out.address == (expected == IdentityStatus::Ok ? address : 0));
    CHECK(out.length == (expected == IdentityStatus::Ok ? r.length : 0));
}

int main() {
    const PhysicalRun contiguous[]{{0x2000, 4096}, {0x3000, 4096}, {0x4000, 4096}};
    const PhysicalRun fragmented[]{{0x2000, 4096}, {0x5000, 4096}};
    const PhysicalRun overlap[]{{0x2000, 4096}, {0x2fff, 4096}};
    const PhysicalRun zero[]{{0, 4096}};
    const PhysicalRun high[]{{0xfffff000, 8192}};
    const PhysicalRun end[]{{~uint64_t(0) - 15, 32}};
    IdentityRequest r{12288, 0, 12288, 4096, 64, 32};
    expect(r, contiguous, 3, IdentityStatus::Ok, 0x2000);
    r = {12288, 4090, 20, 1, 0, 32};
    expect(r, contiguous, 3, IdentityStatus::Ok, 0x2ffa);
    r = {8192, 0, 4096, 4096, 32, 32};
    expect(r, fragmented, 2, IdentityStatus::Ok, 0x2000); // clip before gap
    r.length = 4097;
    expect(r, fragmented, 2, IdentityStatus::Fragmented);
    expect(r, overlap, 2, IdentityStatus::Fragmented);
    r = {8192, 0, 8192, 1, 32, 32};
    expect(r, high, 1, IdentityStatus::AddressWidth);
    r.length = 4096;
    expect(r, high, 1, IdentityStatus::Ok, 0xfffff000);
    r = {32, 0, 16, 1, 64, 32};
    expect(r, end, 1, IdentityStatus::Ok, ~uint64_t(0) - 15);
    r.length = 17;
    expect(r, end, 1, IdentityStatus::AddressOverflow);
    r = {4096, 0, 4096, 1, 64, 32};
    expect(r, zero, 1, IdentityStatus::ZeroPhysicalAddress);
    r = {12288, 1, 100, 4096, 64, 32};
    expect(r, contiguous, 3, IdentityStatus::Alignment);
    r.alignment = 3;
    expect(r, contiguous, 3, IdentityStatus::InvalidArgument);
    r = {12288, 0, 0, 1, 64, 32};
    expect(r, contiguous, 3, IdentityStatus::InvalidArgument);
    r = {12288, 12289, 1, 1, 64, 32};
    expect(r, contiguous, 3, IdentityStatus::DescriptorRange);
    r = {12288, 12288, 1, 1, 64, 32};
    expect(r, contiguous, 3, IdentityStatus::DescriptorRange);
    r = {~uint64_t(0), ~uint64_t(0) - 1, 3, 1, 64, 32};
    expect(r, contiguous, 3, IdentityStatus::DescriptorRange);
    r = {12288, 0, 100, 0, 65, 32};
    expect(r, contiguous, 3, IdentityStatus::InvalidArgument);
    r.addressBits = 64; r.segmentBudget = 0;
    expect(r, contiguous, 3, IdentityStatus::InvalidArgument);
    r.segmentBudget = 32;
    expect(r, nullptr, 0, IdentityStatus::ReaderFailed);
    IdentityResult out{};
    CHECK(validateIdentity(r, nullptr, nullptr, out) == IdentityStatus::InvalidArgument);
    CHECK(out.address == 0 && out.length == 0 && out.segmentsRead == 0);
    CHECK(validateIdentity(r, zeroRun, nullptr, out) == IdentityStatus::ReaderFailed);
    r = {12288, 0, 12288, 1, 64, 2};
    expect(r, contiguous, 3, IdentityStatus::SegmentBudget);
    r = {100, 0, 100, 1, 64, 99};
    CHECK(validateIdentity(r, byteRun, nullptr, out) == IdentityStatus::SegmentBudget);
    CHECK(out.address == 0 && out.length == 0 && out.segmentsRead == 99);
    r.segmentBudget = 100;
    CHECK(validateIdentity(r, byteRun, nullptr, out) == IdentityStatus::Ok);
    CHECK(out.address == 0x1000 && out.length == 100 && out.segmentsRead == 100);
    r = {12288, 0, 1, uint64_t(1) << 63, 64, 32};
    expect(r, contiguous, 3, IdentityStatus::Alignment);

    r = {~uint64_t(0), ~uint64_t(0) - 1, 1, 1, 64, 1};
    CHECK(validateIdentity(r, topRun, nullptr, out) == IdentityStatus::Ok);
    CHECK(out.address == ~uint64_t(0) && out.length == 1);
    const PhysicalRun bit1[]{{1, 2}};
    r = {2, 0, 1, 0, 1, 1};
    expect(r, bit1, 1, IdentityStatus::Ok, 1);
    r.length = 2;
    expect(r, bit1, 1, IdentityStatus::AddressWidth);
    const PhysicalRun bit63[]{{(uint64_t(1) << 63) - 1, 2}};
    r = {2, 0, 1, 0, 63, 1};
    expect(r, bit63, 1, IdentityStatus::Ok, (uint64_t(1) << 63) - 1);
    r.length = 2;
    expect(r, bit63, 1, IdentityStatus::AddressWidth);

    // Deterministic generated subranges: no dependence on wall clock or hardware.
    uint32_t seed = 0x8127;
    for (unsigned i = 0; i < 5000; ++i) {
        seed = seed * 1664525u + 1013904223u;
        const uint64_t offset = seed % 12288;
        seed = seed * 1664525u + 1013904223u;
        const uint64_t length = 1 + seed % (12288 - offset);
        r = {12288, offset, length, 1, 64, 3};
        expect(r, contiguous, 3, IdentityStatus::Ok, 0x2000 + offset);
    }
    // Any changed PA at a run boundary must be rejected, in either direction.
    for (unsigned i = 1; i < 256; ++i) {
        PhysicalRun gap[]{{0x10000, 32}, {0x10020 + i, 32}};
        r = {64, 0, 64, 1, 64, 2};
        expect(r, gap, 2, IdentityStatus::Fragmented);
        gap[1].address = 0x10020 - i;
        expect(r, gap, 2, IdentityStatus::Fragmented);
    }
    printf("Identity tests: %u checks, %u failures\n", checks, failures);
    const int ivrsFailures = runIvrsTests();
    const int topologyFailures = runTopologyTests();
    return failures || ivrsFailures || topologyFailures ? 1 : 0;
}
