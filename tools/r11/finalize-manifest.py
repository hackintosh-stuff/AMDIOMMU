#!/usr/bin/env python3
"""finalize-manifest.py -- write the archive manifest for one capture.

WHY THIS IS A SCRIPT AND NOT A COPY OF capture-round11.sh's block
----------------------------------------------------------------
The manifest must be written AFTER the analysis output exists, and it must
distinguish three categories that round 10 conflated:

  AUTHORITATIVE   the raw inputs, and above all obs-snapshot-used.bin, which is
                  the exact byte string the probe decoded
  DERIVED         analysis/analysis.json -- produced FROM the raw inputs, so it
                  is reproducible and must not be edited by hand
  NOT EVIDENCE    driver-snapshot-later.bin / driver-obs.txt, which are a LATER
                  publication than the one the probe used

Round 10's archive has an analysis.json whose sha256 does not match its own
MANIFEST, because the analyser wrote into the read-only evidence directory after
the manifest was made. This script writes the manifest last, and puts the
analysis output in a subdirectory so the two can never disagree again.

Usage: finalize-manifest.py <capture-dir>
"""
import hashlib
import os
import sys

AUTHORITATIVE = [
    'props.txt', 'props.raw.txt', 'obs-snapshot-used.bin',
    'client.log', 'peer.log', 'load.txt', 'network.txt', 'system.txt',
    'netstat-before.txt', 'netstat-after.txt', 'dmesg.txt',
    'launchd.out', 'launchd.err',
]
DERIVED = ['analysis/analysis.json']
NOT_EVIDENCE = ['driver-snapshot-later.bin', 'driver-obs.txt']


def sha(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for c in iter(lambda: f.read(1 << 20), b''):
            h.update(c)
    return h.hexdigest()


def main():
    cap = sys.argv[1] if len(sys.argv) > 1 else '.'
    run_id = os.path.basename(os.path.abspath(cap))

    lines = []
    lines.append('run_id        : %s' % run_id)
    lines.append('interface     : en2  (RTL8127, MAC 1c:86:0b:3b:0b:bd)')
    lines.append('run_token     : 0xa3dbba85')
    lines.append('declared_batch: 4')
    lines.append('')
    lines.append('HOW TO READ THIS ARCHIVE')
    lines.append('------------------------')
    lines.append('AUTHORITATIVE -- raw inputs. Every conclusion is derived from')
    lines.append('  these and nothing else.')
    lines.append('')
    lines.append('  obs-snapshot-used.bin is THE DRIVER EVIDENCE. It is the exact')
    lines.append('  byte string the probe decoded to produce its verdicts, exported')
    lines.append('  by the probe itself as m2-b2-obs-snapshot-used. Its sha256')
    lines.append('  equals the probe\'s own m2-b2-obs-used-sha256, which')
    lines.append('  capture-round11.sh asserts on the machine before the archive')
    lines.append('  is written. Round 10 could not make this statement: it')
    lines.append('  analysed a publication 43 s later than the one the probe used.')
    lines.append('')
    lines.append('DERIVED -- produced FROM the authoritative inputs. Reproducible')
    lines.append('  by re-running tools/analyze-round11.py against this directory.')
    lines.append('  Do not edit by hand; regenerate instead.')
    lines.append('')
    lines.append('NOT EVIDENCE -- the driver node as ioreg saw it at capture time.')
    lines.append('  That is a LATER publication than the one the probe used. Kept')
    lines.append('  so the gap between the two is a recorded measurement rather')
    lines.append('  than a claim. Never analyse these as if they were the')
    lines.append('  runtime snapshot.')
    lines.append('')

    def block(title, names):
        lines.append('%s:' % title)
        for n in names:
            p = os.path.join(cap, n)
            if os.path.exists(p):
                lines.append('  %s  %10d  %s'
                             % (sha(p), os.path.getsize(p), n))
            else:
                lines.append('  %-64s  MISSING  %s' % ('-', n))
        lines.append('')

    block('AUTHORITATIVE', AUTHORITATIVE)
    block('DERIVED', DERIVED)
    block('NOT EVIDENCE', NOT_EVIDENCE)

    # Anything present that the lists above do not mention: report it rather
    # than silently leaving it unclassified.
    known = set(AUTHORITATIVE) | set(DERIVED) | set(NOT_EVIDENCE) | {'MANIFEST.txt'}
    extra = []
    for root, _dirs, files in os.walk(cap):
        for f in files:
            rel = os.path.relpath(os.path.join(root, f), cap)
            if rel not in known:
                extra.append(rel)
    if extra:
        lines.append('UNCLASSIFIED (present but not in any list above):')
        for e in sorted(extra):
            lines.append('  %s' % e)
        lines.append('')

    lines.append('TIME')
    lines.append('----')
    lines.append('Every monotonic timestamp inside the capture is')
    lines.append('mach_absolute_time (CLOCK_UPTIME_RAW), which equals nanoseconds')
    lines.append('since boot on this host (hw.tbfrequency = 1000000000).')
    lines.append('')
    lines.append('The peer log uses Python\'s monotonic clock with a DIFFERENT')
    lines.append('epoch, so the two are correlated by run token, request id and')
    lines.append('the client\'s source port -- never by subtracting timestamps.')

    out = os.path.join(cap, 'MANIFEST.txt')
    with open(out, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(lines) + '\n')
    print('wrote %s (%d lines)' % (out, len(lines)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
