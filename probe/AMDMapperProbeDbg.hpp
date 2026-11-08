#pragma once
#include <IOKit/IOTypes.h>

// amdiommu_dbg is an 8-bit publication mask. It never changes the mapper's
// behaviour: the state machine, DMA path and power transitions run exactly as
// before, only the optional IORegistry evidence is suppressed.
namespace amdiommu_dbg {

enum : UInt32 {
    kBase = 1u << 0,       // startup mode, controller and domain skeleton
    kSelect = 1u << 1,     // device selection and profile admission
    kAttach = 1u << 2,     // claim/attach process and hook policy
    kDiscovery = 1u << 3,  // IVRS and PCI capability discovery
    kMapping = 1u << 4,    // mapper, domains, capacity and snapshots
    kPM = 1u << 5,         // sleep/wake state and transitions
    kRaw = 1u << 6,        // large OSData blobs and snapshot-domains
    kDebug = 1u << 7,      // Debug-build-only M2 evidence
    kAll = 0xFFu,
};

// The default is intentionally quiet: tools must opt in to the evidence group
// they consume. The one always-published key is amdiommu-dbg, so a reader can
// tell a masked key from a genuinely missing one.
static constexpr UInt32 kDefault = 0x00;

inline bool On(UInt32 mask, UInt32 group) {
    return (mask & group) != 0;
}

// PE_parse_boot_argn may hand an all-digit value back as a converted 32-bit
// integer inside the caller's buffer. Requiring the 0x prefix makes the value
// arrive as text, the same convention amdiommu_devices uses with its n-prefix.
inline bool Parse(const char *text, UInt32 *out) {
    if (!text || !out) return false;
    if (text[0] != '0' || (text[1] != 'x' && text[1] != 'X')) return false;
    UInt32 value = 0;
    UInt32 digits = 0;
    for (const char *p = text + 2; *p; ++p) {
        UInt32 nibble;
        if (*p >= '0' && *p <= '9') nibble = (UInt32)(*p - '0');
        else if (*p >= 'a' && *p <= 'f') nibble = (UInt32)(*p - 'a' + 10);
        else if (*p >= 'A' && *p <= 'F') nibble = (UInt32)(*p - 'A' + 10);
        else return false;
        if (++digits > 8) return false;
        value = (value << 4) | nibble;
    }
    if (!digits || (value & ~kAll)) return false;
    *out = value;
    return true;
}

} // namespace amdiommu_dbg
