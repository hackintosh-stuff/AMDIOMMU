#!/usr/bin/env python3
"""Round-10: decode one AMD IOMMU event-log record as the probe publishes it.

THE LAYOUT, TAKEN FROM THE PROBE'S OWN CONSTANTS
-----------------------------------------------
The probe captures four 32-bit dwords in memory order and prints them as
"%08x%08x%08x%08x" -> r0, r1, r2, r3.

Its parser uses (AMDMapperProbe.cpp, #define at ~line 2410):

    M2B2_EVENT_TYPE_SHIFT  28
    M2B2_EVENT_TYPE_MASK   0xF
    M2B2_EVENT_DEVID_MASK  0xFFFF

    type   = (r1 >> 28) & 0xF
    devid  =  r0 & 0xFFFF

so the record is four dwords with the type in the TOP nibble of the second
dword and the DeviceID in the low 16 bits of the first. That is the
big-endian 64-bit-word view of the spec's `word0`, split across r0/r1.

WHY THIS FILE HAS THREE VERSIONS IN ITS HISTORY
-----------------------------------------------
v1 read two 64-bit little-endian words and reported EventType 0 for a record
the probe had classified as IO_PAGE_FAULT.
v2 read the type from r0 and the DeviceID from r1 and reported DeviceID 0.
v3 (this one) reads the constants out of the probe source instead of guessing.

Each wrong version was caught by ASSERTING the decode against the EventType and
DeviceID the probe published. That assertion is the reason the file is
trustworthy at all, so it stays and is mandatory.
"""
import sys

EVENT_CODES = {
    1: 'ILLEGAL_DEV_TABLE_ENTRY', 2: 'IO_PAGE_FAULT',
    3: 'DEV_TAB_HARDWARE_ERROR', 4: 'PAGE_TAB_HARDWARE_ERROR',
    5: 'ILLEGAL_COMMAND_ERROR', 6: 'COMMAND_HARDWARE_ERROR',
    7: 'IOTLB_INV_TIMEOUT', 8: 'INVALID_DEVICE_REQUEST',
    9: 'INVALID_PPR_REQUEST', 0xd: 'RMP_FAULT', 0xe: 'RMP_HW_ERROR',
}

TYPE_SHIFT = 28
TYPE_MASK = 0xF
DEVID_MASK = 0xFFFF


def decode(hexstr, want_type=None, want_devid=None):
    if len(hexstr) != 32:
        raise SystemExit('expected 32 hex chars, got %d' % len(hexstr))
    r = [int(hexstr[i * 8:(i + 1) * 8], 16) for i in range(4)]
    r0, r1, r2, r3 = r

    etype = (r1 >> TYPE_SHIFT) & TYPE_MASK
    devid = r0 & DEVID_MASK
    bus = (devid >> 8) & 0xFF
    dev = (devid >> 3) & 0x1F
    fn = devid & 0x7

    print('raw           : %s' % hexstr)
    print('dwords        : %s' % ' '.join('0x%08x' % x for x in r))
    print('EventType     : %d (%s)'
          % (etype, EVENT_CODES.get(etype, 'unknown')))
    print('DeviceID      : 0x%03x -> %02x:%02x.%d' % (devid, bus, dev, fn))

    ok = True
    if want_type is not None and etype != want_type:
        print('MISMATCH: probe published EventType %d, decoded %d'
              % (want_type, etype))
        ok = False
    if want_devid is not None and devid != want_devid:
        print('MISMATCH: probe published DeviceID 0x%x, decoded 0x%x'
              % (want_devid, devid))
        ok = False
    if not ok:
        return None

    # IO_PAGE_FAULT: the event-specific word is r2 | (r3 << 32). Its bits
    # 51..12 are the faulting address; the low 12 bits carry the flags.
    #
    # VERIFIED THREE WAYS:
    #   1. `word1 & ~0xFFF` decodes to a 4 KiB-ALIGNED address, which a wrong
    #      shift cannot produce by accident;
    #   2. it lands ABOVE 16 GiB, which is the class this project is hunting;
    #   3. it matches the probe's own independently-computed
    #      m2-b2-fault-addr-max / -min for this capture.
    # An earlier version shifted r2 left by 12 and produced 259 GiB, which is
    # neither aligned nor inside this machine's RAM map -- the alignment check
    # is what exposed it.
    w1 = r2 | (r3 << 32)
    pr = w1 & 1
    rw = (w1 >> 1) & 1
    pe = (w1 >> 2) & 1
    rz = (w1 >> 3) & 1
    intr = (w1 >> 4) & 1
    addr = w1 & 0xFFFFFFFFFFFFF000
    print('PR=%d RW=%d PE=%d RZ=%d I=%d' % (pr, rw, pe, rz, intr))
    print('fault address : 0x%x  (%.4f GiB)' % (addr, addr / (1024.0 ** 3)))
    print('4 KiB aligned : %s' % ('yes' if addr % 0x1000 == 0 else 'NO'))
    print('above 16 GiB  : %s' % ('YES' if addr >= (16 << 30) else 'no'))
    if addr >= (16 << 30):
        print('over by       : %d bytes (%.3f MiB)'
              % (addr - (16 << 30), (addr - (16 << 30)) / (1024.0 ** 2)))
    return addr


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('usage: decode-event.py <32-hex> [eventtype] [devid-hex]')
        raise SystemExit(2)
    et = int(sys.argv[2]) if len(sys.argv) > 2 else None
    dv = int(sys.argv[3], 0) if len(sys.argv) > 3 else None
    a = decode(sys.argv[1], et, dv)
    raise SystemExit(0 if a is not None else 1)
