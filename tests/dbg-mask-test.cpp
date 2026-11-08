#include "AMDMapperProbeDbg.hpp"

#include <cassert>
#include <cstdio>

int main() {
    static_assert(amdiommu_dbg::kDefault == 0x00,
                  "the production default must publish no optional evidence");
    UInt32 mask = 0xFF;
    assert(amdiommu_dbg::Parse("0x00", &mask) && mask == 0x00);
    assert(amdiommu_dbg::Parse("0x1F", &mask) && mask == 0x1F);
    assert(amdiommu_dbg::Parse("0x00000050", &mask) && mask == 0x50);
    assert(!amdiommu_dbg::Parse("0x100", &mask));
    assert(!amdiommu_dbg::Parse("50", &mask));
    assert(!amdiommu_dbg::Parse("0x", &mask));
    std::puts("dbg-mask-test: 0x00 default and parser PASS");
    return 0;
}
