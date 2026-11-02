#!/usr/bin/env python3
"""Negative tests for tools/r18/analyze.py against the REAL round-18 capture.

Purpose: prove the 19 checks are not vacuous. Each case mutates exactly the
field one check consumes and requires that check (and only it, as far as the
mutation goes) to fail. The unmutated capture must pass first.

Usage: py -3 tools/r18/test-analyze.py CAPTURE
"""
import shutil
import struct
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import analyze as A  # noqa: E402

STD_HEADER, STD_REC = A.STD_HEADER, A.STD_RECORD_BYTES
DRV_HEADER, DRV_REC = A.DRIVER_HEADER, A.DRIVER_RECORD_BYTES


def std_at(req, offset):
    """Accepted requests 1..12 occupy index handle-1 == req-1."""
    return STD_HEADER + (req - 1) * STD_REC + offset


def drv_at(req, offset):
    return DRV_HEADER + (req - 1) * DRV_REC + offset


def poke(path, offset, fmt, value):
    b = bytearray(path.read_bytes())
    struct.pack_into('<' + fmt, b, offset, value)
    path.write_bytes(bytes(b))


def peek(path, offset, fmt):
    return struct.unpack_from('<' + fmt, path.read_bytes(), offset)[0]


def failing(cap):
    try:
        result = A.analyze(cap)
    except Exception as exc:                      # refused before checks
        return {'<refused>'} | set(), str(exc)
    return ({c['id'] for c in result['checks'] if c['state'] == 'fail'},
            [(c['id'], str(c.get('detail'))[:120])
             for c in result['checks'] if c['state'] != 'ok'])


def expect(cap, mutate, want, label, passed):
    mutate()
    ids, info = failing(cap)
    assert want in ids, '%s: expected %s to fail, got %s' % (label, want, info)
    passed.append(label)


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    src = Path(sys.argv[1])
    passed = []
    with tempfile.TemporaryDirectory() as tmp:
        cap = Path(tmp) / 'cap'
        shutil.copytree(src, cap)
        std = cap / 'r18-std-raw.bin'
        drv = cap / 'r18-driver-raw.bin'
        props = cap / 'props.txt'
        driver = cap / 'driver-obs.txt'

        result = A.analyze(cap)
        assert result['ok'] is True, 'the unmutated capture must pass first'
        passed.append('baseline-passes')

        def m_no_unmap():
            poke(std, std_at(5, 28), 'I', peek(std, std_at(5, 28), 'I') & ~2)

        expect(cap, m_no_unmap, 'request05-standard-map-to-unmap',
               'cleared-unmap-flag-rejected', passed)

        def undo5():
            poke(std, std_at(5, 28), 'I', peek(std, std_at(5, 28), 'I') | 2)

        undo5()

        def m_mapaddr():
            poke(std, std_at(3, 48), 'Q', peek(std, std_at(3, 48), 'Q') + 8)

        expect(cap, m_mapaddr, 'request03-standard-map-to-unmap',
               'moved-map-address-rejected', passed)
        poke(std, std_at(3, 48), 'Q', peek(std, std_at(3, 48), 'Q') - 8)

        def m_identity():
            # Make the TX descriptor carry the PHYSICAL address, i.e. the
            # identity fallback this round must never take.
            pa = peek(drv, drv_at(7, 56), 'Q')
            poke(drv, drv_at(7, 352), 'Q', pa)

        expect(cap, m_identity, 'request07-standard-map-to-unmap',
               'identity-descriptor-rejected', passed)

        def m_phys():
            poke(drv, drv_at(2, 56), 'Q', peek(drv, drv_at(2, 56), 'Q') + 0x1000)

        expect(cap, m_phys, 'request02-standard-map-to-unmap',
               'mutated-physical-pa-rejected', passed)

        def m_free_order():
            poke(std, std_at(4, 200), 'Q', 0)     # tFree before the unmap

        expect(cap, m_free_order, 'request04-standard-map-to-unmap',
               'free-without-unmap-time-rejected', passed)

        text = props.read_text(encoding='utf-8', errors='replace')
        original = text

        def m_insert():
            props.write_text(text.replace('"m2-3c-insert-calls" = "0x0"',
                                          '"m2-3c-insert-calls" = "0x1"'),
                             encoding='utf-8')

        expect(cap, m_insert, 'probe-counters-and-record-count',
               'iovmInsert-nonzero-rejected', passed)
        props.write_text(original, encoding='utf-8')

        dtext = driver.read_text(encoding='utf-8', errors='replace')

        def m_mode():
            driver.write_text(dtext.replace('native-mbuf-standard-iomapper-v1',
                                            'native-mbuf-explicit-iova-v1'),
                              encoding='utf-8')

        expect(cap, m_mode, 'standard-mapper-mode-armed',
               'non-standard-mode-rejected', passed)
        driver.write_text(dtext, encoding='utf-8')

        def m_accepts():
            props.write_text(original.replace('"m2-3c-map-ok" = "0xc"',
                                              '"m2-3c-map-ok" = "0xd"'),
                             encoding='utf-8')

        expect(cap, m_accepts, 'probe-counters-and-record-count',
               'probe-driver-count-mismatch-rejected', passed)
        props.write_text(original, encoding='utf-8')

    print('%d negative checks passed: %s' % (len(passed), ', '.join(passed)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
