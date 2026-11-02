#!/usr/bin/env python3
"""Negative tests for tools/r17/analyze.py against the REAL round-17 capture.

The point is not "the analyzer passes" (that is the run's job) but "the
analyzer is not vacuous": each mutation below must make a specific check fail,
and the mutation is applied to the exact field that check consumes.

Usage: py -3 tools/r17/test-analyze.py CAPTURE
"""
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import analyze as X  # noqa: E402

DOM = X.DOMAIN_HEADER
DOMREC = X.DOMAIN_RECORD_BYTES
DRV = X.DRIVER_HEADER
DRVREC = X.DRIVER_RECORD_BYTES


def dom_at(i, offset):
    return DOM + i * DOMREC + offset


def drv_at(i, offset):
    return DRV + i * DRVREC + offset


def load(cap):
    p = X.A.hexprops((cap / 'props.txt').read_text(encoding='utf-8', errors='replace'))
    raw = (cap / 'props.raw.txt').read_text(encoding='utf-8', errors='replace')
    blobs = [X.raw_export(cap, raw, key, name) for key, name in (
        ('m2-3b-domain-raw', 'r17-domain-raw.bin'),
        ('m2-3b-pt-raw', 'r17-pt-raw.bin'),
        ('m2-3b-driver-raw', 'r17-driver-raw.bin'),
        ('m2-b2-obs-snapshot-used', 'obs-snapshot-used.bin'))]
    logs = {n: (cap / n).read_text(encoding='utf-8', errors='replace')
            for n in ('client.log', 'peer.log')}
    return p, blobs, logs


def poke(blob, offset, fmt, value):
    b = bytearray(blob)
    struct.pack_into('<' + fmt, b, offset, value)
    return bytes(b)


def run(cap, mutate=None, metadata=None):
    p, blobs, logs = load(cap)
    blobs, logs = list(blobs), dict(logs)
    if mutate:
        mutate(p, blobs, logs)
    meta = metadata if metadata is not None else X.capture_metadata(cap)
    try:
        return X.analyze_payloads(p, *blobs, logs, metadata=meta)
    except (X.Refused, KeyError, TypeError, ValueError, struct.error) as exc:
        return {'ok': False, 'refused': str(exc), 'checks': []}


def failing(result):
    return {c['id'] for c in result.get('checks', []) if c['state'] == 'fail'}


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    cap = Path(sys.argv[1])
    passed = []

    base = run(cap)
    assert base['ok'] is True, 'the unmutated capture must pass first'
    passed.append('baseline-passes')

    def m_pte(p, blobs, logs):
        # request 4 is a two-page generation: move its second leaf elsewhere.
        at = dom_at(3, 256 + 128 + 8)   # physical[16] then mapPte[1]
        leaf = struct.unpack_from('<Q', blobs[0], at)[0]
        blobs[0] = poke(blobs[0], at, 'Q', leaf + 0x1000)

    r = run(cap, m_pte)
    assert 'request04-native-map-to-retire-free' in failing(r), sorted(failing(r))
    passed.append('mutated-map-pte-rejected')

    def m_phys(p, blobs, logs):
        addr = struct.unpack_from('<Q', blobs[2], drv_at(0, 56))[0]
        blobs[2] = poke(blobs[2], drv_at(0, 56), 'Q', addr + 0x10)

    r = run(cap, m_phys)
    assert 'request01-native-map-to-retire-free' in failing(r), sorted(failing(r))
    passed.append('mutated-driver-physical-rejected')

    def m_identity(p, blobs, logs):
        # Program the descriptor with the PHYSICAL address: the identity
        # fallback this round must never take.
        pa = struct.unpack_from('<Q', blobs[2], drv_at(1, 56))[0]
        blobs[2] = poke(blobs[2], drv_at(1, 352), 'Q', pa)

    r = run(cap, m_identity)
    assert 'request02-native-map-to-retire-free' in failing(r), sorted(failing(r))
    passed.append('identity-descriptor-rejected')

    def m_early_free(p, blobs, logs):
        retire = struct.unpack_from('<Q', blobs[2], drv_at(2, 48))[0]
        blobs[2] = poke(blobs[2], drv_at(2, 320), 'Q', retire - 1)

    r = run(cap, m_early_free)
    assert 'request03-native-map-to-retire-free' in failing(r), sorted(failing(r))
    passed.append('free-before-retire-rejected')

    def m_payload(p, blobs, logs):
        text = logs['peer.log']
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if line.startswith('peer_recv ') and ' req=7 ' in line:
                old = 'payload='
                at = line.index(old) + len(old)
                flipped = line[at:at + 2]
                new = 'ff' if flipped != 'ff' else '00'
                lines[i] = line[:at] + new + line[at + 2:]
                break
        else:
            raise AssertionError('peer_recv req=7 not found')
        logs['peer.log'] = '\n'.join(lines) + '\n'

    r = run(cap, m_payload)
    assert 'full-application-bytes-32' in failing(r), sorted(failing(r))
    passed.append('mutated-peer-bytes-rejected')

    def m_status(p, blobs, logs):
        blobs[0] = poke(blobs[0], dom_at(19, 56), 'I', 2)  # no map invalidation

    r = run(cap, m_status)
    assert 'request20-native-map-to-retire-free' in failing(r), sorted(failing(r))
    passed.append('missing-map-invalidation-rejected')

    def m_handle(p, blobs, logs):
        blobs[2] = poke(blobs[2], drv_at(30, 24), 'Q', 999)  # witness handle

    r = run(cap, m_handle)
    assert 'request31-native-map-to-retire-free' in failing(r), sorted(failing(r))
    passed.append('handle-mismatch-rejected')

    meta = dict(X.capture_metadata(cap))
    meta['cleanup'] = 'PINNED-outstanding-no-DTE-restore'
    r = run(cap, None, metadata=meta)
    assert 'native-mbuf-mode-and-binary-binding' in failing(r), sorted(failing(r))
    passed.append('pinned-detach-rejected')

    meta = dict(X.capture_metadata(cap))
    meta['installedDriverVersion'] = '1.1.201'
    r = run(cap, None, metadata=meta)
    assert 'native-mbuf-mode-and-binary-binding' in failing(r), sorted(failing(r))
    passed.append('round16-binary-rejected')

    def m_pages(p, blobs, logs):
        # Claim one page for a generation that really used two.
        blobs[0] = poke(blobs[0], dom_at(3, 44), 'I', 1)

    r = run(cap, m_pages)
    assert 'request04-native-map-to-retire-free' in failing(r), sorted(failing(r))
    passed.append('wrong-page-count-rejected')

    print('%d negative checks passed: %s' % (len(passed), ', '.join(passed)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
