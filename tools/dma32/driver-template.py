"""Use the ordinary device mapper with a 32-bit DMA address constraint.

The same fixed, RX-group and packet-TX commands keep their existing lifetime
and segmentation. Only normal AMDIOMMU mode requests low device addresses;
other mappers and the historical experimental paths retain their old width.
Physical buffers are not restricted to low RAM: the IOMapper translates them.
"""

COMMAND_OLD = ('IODMACommand::withSpecification(kIODMACommandOutputHost64, '
               '64, 0, IODMACommand::kMapped, 0, 1, mapper, NULL)')
COMMAND_NEW = ('IODMACommand::withSpecification(kIODMACommandOutputHost64, '
               'r44NormalMapped ? 32 : 64, 0, IODMACommand::kMapped, '
               '0, 1, mapper, NULL)')

READY_OLD = '    r47PublishPM("ready");\n'
READY_NEW = READY_OLD + '''    if (r44NormalMapped)
        setProperty("rtl812x-r48-dma-address-bits", (UInt64)32, 64);
'''


def patch(cpp, setup, vtd):
    if cpp.count(READY_OLD) != 1:
        raise SystemExit('refused: round48 normal DMA configuration anchor')
    # Three fixed objects, one RX-group constructor and one TX-pool
    # constructor cover all ordinary DMA owners without touching legacy code.
    for name, text, count in (('fixed', setup, 3), ('RX/TX', vtd, 2)):
        if text.count(COMMAND_OLD) != count:
            raise SystemExit('refused: round48 %s command constructor count' % name)
    return (cpp.replace(READY_OLD, READY_NEW, 1),
            setup.replace(COMMAND_OLD, COMMAND_NEW),
            vtd.replace(COMMAND_OLD, COMMAND_NEW))


def is_current(cpp, setup, vtd):
    return (cpp.count(READY_NEW) == 1 and
            setup.count(COMMAND_NEW) == 3 and COMMAND_OLD not in setup and
            vtd.count(COMMAND_NEW) == 2 and COMMAND_OLD not in vtd)
