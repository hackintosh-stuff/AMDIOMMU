"""Use 64-page ordinary RX mappings through the existing grouped DMA path.

The original setup, replacement, down/up and free methods derive their
geometry from this shift. The same 1024 RX slots now use 16 descriptors
of 64 pages (256 KiB) each; buffers, per-slot addresses and ownership stay
unchanged. Ordinary networking therefore uses mappings beyond 32 pages.
"""

SHIFT_OLD = '#define kRxMemBaseShift 4\n'
SHIFT_NEW = '#define kRxMemBaseShift 6\n'


SHIFT_128 = '#define kRxMemBaseShift 7\n'


def patch(hpp, wide=False):
    if hpp.count(SHIFT_OLD) != 1:
        raise SystemExit('refused: round49 RX mapping batch shift anchor')
    return hpp.replace(SHIFT_OLD, SHIFT_128 if wide else SHIFT_NEW, 1)


def is_current(hpp, wide=False):
    want = SHIFT_128 if wide else SHIFT_NEW
    return hpp.count('#define kRxMemBaseShift ') == 1 and hpp.count(want) == 1


def upgrade_128(hpp):
    """Only upgrade the accepted 64-page header; leave unrelated edits alone."""
    return hpp.replace(SHIFT_NEW, SHIFT_128, 1) if is_current(hpp) else hpp
