"""Publish the PCI requester and actual mapper identity for each Lucy instance.

The ordinary DMA path already obtains its mapper from its own pciDevice.
R52 exposes that immutable association so captures can select two identical
RTL8127 devices by identity instead of class matching order or BSD unit number.
The requester is also available with AMDIOMMU off; absent mapper/domain IDs
are zero. No DMA command or power-transition behavior changes in this layer.
"""

READY_OLD = '''    r47PublishPM("ready");
    if (r44NormalMapped)
        setProperty("rtl812x-r48-dma-address-bits", (UInt64)32, 64);
'''

IDENTITY = '''    /* Round52: identity belongs to this PCI device and its actual mapper.
     * The mapper publishes its domain before binding iommu-parent, so these
     * values remain valid for this driver's whole lifetime. */
    {
        const UInt64 requester = ((UInt64)pciDevice->getBusNumber() << 8) |
            ((UInt64)pciDevice->getDeviceNumber() << 3) |
            (UInt64)pciDevice->getFunctionNumber();
        OSNumber *domain = mapper ? OSDynamicCast(OSNumber,
            mapper->getProperty("r44-domain-id")) : NULL;
        setProperty("rtl812x-r52-requester", requester, 64);
        setProperty("rtl812x-r52-mapper-id",
            mapper ? (UInt64)mapper->getRegistryEntryID() : (UInt64)0, 64);
        setProperty("rtl812x-r52-domain-id",
            domain ? domain->unsigned64BitValue() : (UInt64)0, 64);
    }
'''

READY_NEW = READY_OLD + IDENTITY


def patch(cpp):
    if cpp.count(READY_OLD) != 1:
        raise SystemExit('refused: round52 per-device identity anchor')
    return cpp.replace(READY_OLD, READY_NEW, 1)


def is_current(cpp):
    return cpp.count(READY_NEW) == 1
