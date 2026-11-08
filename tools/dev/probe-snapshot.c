// probe-snapshot.c - Ask every org_maz1_AMDMapperProbe instance to republish its
// snapshot (setProperties {"RefreshSnapshot": true}).
// Formerly R44Snapshot.
//
// The probe publishes mapper-map-ok / iommu-dte-active / invalidation counters
// only when someone asks: PublishMappings() runs from setProperties, from attach
// and from the sleep/wake boundary. Without this poke those properties keep their
// attach-time values (all zero) even while the device is happily doing mapped DMA.
//
// Build: clang -framework IOKit -framework CoreFoundation -o probe-snapshot probe-snapshot.c
// Run:   sudo ./probe-snapshot
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <stdio.h>

int main(void) {
    CFMutableDictionaryRef matching = IOServiceMatching("org_maz1_AMDMapperProbe");
    if (!matching) {
        fprintf(stderr, "IOServiceMatching failed\n");
        return 1;
    }

    io_iterator_t iterator = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iterator);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "IOServiceGetMatchingServices: 0x%x\n", kr);
        return 1;
    }

    int poked = 0;
    io_service_t service = IO_OBJECT_NULL;
    while ((service = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
        CFMutableDictionaryRef properties = CFDictionaryCreateMutable(
            kCFAllocatorDefault, 1, &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks);
        if (!properties)
            break;
        CFDictionarySetValue(properties, CFSTR("RefreshSnapshot"), kCFBooleanTrue);

        kr = IORegistryEntrySetCFProperties(service, properties);
        char name[128] = {0};
        uint64_t entryID = 0;
        IORegistryEntryGetName(service, name);
        IORegistryEntryGetRegistryEntryID(service, &entryID);
        printf("%-24s id=0x%llx setProperties -> 0x%x\n", name,
               (unsigned long long)entryID, kr);
        if (kr == KERN_SUCCESS)
            poked++;

        CFRelease(properties);
        IOObjectRelease(service);
    }
    IOObjectRelease(iterator);
    printf("poked %d instance(s)\n", poked);
    return poked > 0 ? 0 : 2;
}
