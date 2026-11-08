#pragma once
#include <IOKit/IOMapper.h>

// ABI compilation scaffold ONLY. No matching personality is supplied.
// This class cannot be enabled with a boot argument or a compile-time switch.
// Do not install: IOMapper and IOMapper::start have global side effects.
class org_example_AMDIdentityMapper : public IOMapper {
    OSDeclareDefaultStructors(org_example_AMDIdentityMapper);
protected:
    bool initHardware(IOService *provider) override;
public:
    bool start(IOService *provider) override;
    uint64_t getPageSize() const override;
    IOReturn iovmMapMemory(IOMemoryDescriptor *memory, uint64_t descriptorOffset,
        uint64_t length, uint32_t mapOptions,
        const IODMAMapSpecification *mapSpecification, IODMACommand *dmaCommand,
        const IODMAMapPageList *pageList, uint64_t *mapAddress,
        uint64_t *mapLength) override;
    IOReturn iovmUnmapMemory(IOMemoryDescriptor *memory, IODMACommand *dmaCommand,
        uint64_t mapAddress, uint64_t mapLength) override;
    IOReturn iovmInsert(uint32_t options, uint64_t mapAddress, uint64_t offset,
        uint64_t physicalAddress, uint64_t length) override;
    uint64_t mapToPhysicalAddress(uint64_t mappedAddress) override;
};
