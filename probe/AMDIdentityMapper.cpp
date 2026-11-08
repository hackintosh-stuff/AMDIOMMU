#include "AMDIdentityMapper.hpp"
#include <mach/kmod.h>

OSDefineMetaClassAndStructors(org_example_AMDIdentityMapper, IOMapper);

bool org_example_AMDIdentityMapper::start(IOService *) {
    // Intentionally BEFORE any superclass start, IORegistry publication, or
    // hardware initialization. IOMapper::start can publish the system mapper.
    return false;
}
bool org_example_AMDIdentityMapper::initHardware(IOService *) { return false; }
uint64_t org_example_AMDIdentityMapper::getPageSize() const { return 4096; }
IOReturn org_example_AMDIdentityMapper::iovmMapMemory(
    IOMemoryDescriptor *, uint64_t, uint64_t, uint32_t,
    const IODMAMapSpecification *, IODMACommand *, const IODMAMapPageList *,
    uint64_t *mapAddress, uint64_t *mapLength) {
    if (mapAddress) *mapAddress = 0;
    if (mapLength) *mapLength = 0;
    return kIOReturnUnsupported;
}
IOReturn org_example_AMDIdentityMapper::iovmUnmapMemory(
    IOMemoryDescriptor *, IODMACommand *, uint64_t, uint64_t) {
    return kIOReturnUnsupported;
}
IOReturn org_example_AMDIdentityMapper::iovmInsert(
    uint32_t, uint64_t, uint64_t, uint64_t, uint64_t) {
    return kIOReturnUnsupported;
}
uint64_t org_example_AMDIdentityMapper::mapToPhysicalAddress(uint64_t) {
    return 0; // Never report a successful identity translation in this scaffold.
}

extern "C" {
extern kern_return_t _start(kmod_info_t *, void *);
extern kern_return_t _stop(kmod_info_t *, void *);
KMOD_EXPLICIT_DECL(org.example.AMDIdentityMapper, "0.1.0", _start, _stop);
__attribute__((visibility("hidden"))) kmod_start_func_t *_realmain = nullptr;
__attribute__((visibility("hidden"))) kmod_stop_func_t *_antimain = nullptr;
__attribute__((visibility("hidden"))) int _kext_apple_cc = __APPLE_CC__;
}
