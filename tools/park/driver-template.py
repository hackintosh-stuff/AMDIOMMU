# R64 requester DMA park/restore hooks for RTL812xLucy.

HELPER = r"""
static IOReturn r64RequesterDMA(IOMapper *mapper, IOPCIDevice *pci, UInt32 operation)
{
    if (!mapper || !pci) return kIOReturnNotReady;
    const OSSymbol *key = OSSymbol::withCString("SetRequesterDMAAccess");
    if (!key) return kIOReturnNoMemory;
    const IOReturn result = mapper->callPlatformFunction(key, false, pci,
        (void *)(uintptr_t)operation, NULL, NULL);
    key->release();
    return result;
}

"""
ENABLE_OLD = '    pciDevice->open(this);'
ENABLE_NEW = """    if (!pciDevice->open(this)) goto done;
    if (r44NormalMapped) {
        result = r64RequesterDMA(mapper, pciDevice, 2);
        if (result != kIOReturnSuccess) {
            pciDevice->close(this);
            goto done;
        }
    }

"""
DISABLE_OLD = """    clearRxTxRings();
    r44PublishNormalDMA(false);"""
DISABLE_NEW = """    clearRxTxRings();
    if (r44NormalMapped)
        result = r64RequesterDMA(mapper, pciDevice, 1);
    r44PublishNormalDMA(false);"""
def once(text, old, new, label):
    if text.count(old) != 1:
        raise SystemExit('R64 %s anchor count %d' % (label, text.count(old)))
    return text.replace(old, new, 1)
def is_current(cpp):
    return (HELPER.strip() in cpp and ENABLE_NEW in cpp and DISABLE_NEW in cpp and
            cpp.count('r64RequesterDMA(mapper, pciDevice, 2)') == 1 and
            cpp.count('r64RequesterDMA(mapper, pciDevice, 1)') == 1)
def patch(cpp):
    if HELPER.strip() in cpp:
        if not is_current(cpp): raise SystemExit('R64 Lucy lifecycle is stale/partial')
        return cpp
    sig='IOReturn RTL8125::enable(IONetworkInterface *netif)'
    if cpp.count(sig)!=1: raise SystemExit('R64 expected one enable()')
    cpp=cpp.replace(sig,HELPER+sig,1)
    cpp=once(cpp,ENABLE_OLD,ENABLE_NEW,'enable restore before DMA')
    sig='IOReturn RTL8125::disable(IONetworkInterface *netif)'
    if cpp.count(sig)!=1: raise SystemExit('R64 expected one disable()')
    start=cpp.index(sig); end=cpp.index('\n}\n',start)+3
    body=cpp[start:end]
    body=once(body,'    UInt64 t;\n','    UInt64 t;\n    IOReturn result = kIOReturnSuccess;\n','disable result')
    body=once(body,DISABLE_OLD,DISABLE_NEW,'disable park after RX rebuild')
    body=once(body,'    return kIOReturnSuccess;\n','    return result;\n','disable error propagation')
    cpp=cpp[:start]+body+cpp[end:]
    if not is_current(cpp): raise SystemExit('R64 generated Lucy lifecycle self-check failed')
    return cpp
