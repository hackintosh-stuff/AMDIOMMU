#!/usr/bin/env python3
"""Preflight: refuse to deploy a run that cannot possibly succeed.

This project lost seven hardware runs in round 21 to environment problems that
were all detectable BEFORE rebooting, and each one cost ~4 minutes plus a manual
diagnosis:

  * the EFI partition was not mounted              -> diskutil info failed
  * the default route was on en2, not the mgmt en0 -> deploy refused
  * the load daemon's plist still said `round20load` -> launchd bootstrap I/O error
  * the peer's UDP port was blocked by the firewall  -> acked=0, looked like a TX fault
  * the peer process had already exited              -> acked=0, looked like a TX fault
  * token.txt was missing/wrong owner                -> load.py died at startup
  * the installed kext version was stale             -> wrong build measured

The last two are the dangerous ones: `acked=0` is indistinguishable from a
translation bug in the artifact, so an environment failure masquerades as a
functional failure and sends the investigation in the wrong direction.

Every check states what it verified and what to do about it. Exit code is 0 only
when the machine is actually ready to produce a meaningful run.
"""
import json
import os
import pathlib
import plistlib
import re
import socket
import subprocess
import sys
from protocol import REQUESTS

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]

EFI_UUID = '7A8D47A3-44C8-47E7-B488-A4C24DB5AC82'
EFI_SIZE = 272629760
WHOLE_SIZE = 128035676160
WHOLE_MODEL = 'SanDisk SD8SNAT-128G-1006'
# Round23: the operator reaches this Mac over the NanoKVM RNDIS link, because the
# USB NIC is disabled for the whole round (see the module docstring below).
MGMT_IFACE = 'en3'
MGMT_ADDR = '10.44.51.100'
TARGET_IFACE = 'en2'
PEER = ('192.168.50.122', 9110)
# The firewall rule name is documented in README ("peer 对端：防火墙规则与端口")
# and referenced here. Round 21 used a different name in three places
# (Round21Peer9110 in this file, the docs, and the ad-hoc command that created
# it), which is exactly how "the rule exists but traffic still fails" happens.
PEER_RULE = 'RTL812x-IOMMU-Peer-UDP-9110'
DAEMON = '/Library/LaunchDaemons/org.example.round21load.plist'
LOAD_DIR = '/Users/ling/r21load'

ok, bad = [], []


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def check(name, fn):
    try:
        detail = fn()
        ok.append((name, detail))
    except Exception as exc:
        bad.append((name, str(exc)))


def efi():
    mnt = pathlib.Path('/Volumes/EFI')
    if not mnt.is_dir():
        raise RuntimeError('EFI not mounted: sudo diskutil mount disk2s1')
    info = plistlib.loads(run(['diskutil', 'info', '-plist', str(mnt)]).stdout.encode())
    if info.get('DiskUUID', '').upper() != EFI_UUID:
        raise RuntimeError('EFI UUID is %r, not the target disk' % info.get('DiskUUID'))
    if info.get('Size') != EFI_SIZE:
        raise RuntimeError('EFI size %r != %d' % (info.get('Size'), EFI_SIZE))
    whole = plistlib.loads(
        run(['diskutil', 'info', '-plist', info['ParentWholeDisk']]).stdout.encode())
    if whole.get('TotalSize') != WHOLE_SIZE or WHOLE_MODEL not in str(whole):
        raise RuntimeError('parent disk is not the target SanDisk')
    return 'disk2s1 %d B, writable=%s' % (info['Size'], info.get('Writable'))


def mgmt_route():
    # The management interface must carry its address: that is what the operator
    # session arrived on, and an interface without one is not a management path.
    iface = run(['ifconfig', MGMT_IFACE]).stdout
    if MGMT_ADDR not in iface:
        raise RuntimeError('%s has no %s: the RNDIS link to NanoKVM is down'
                           % (MGMT_IFACE, MGMT_ADDR))
    # ROUND 23: the default route is expected on the TARGET interface, not on the
    # management one. With the USB NIC disabled en2 is the only path off this
    # host, and load.py requires the peer to be reachable through it. Checking
    # that here is what turns "the run had no peer" into a preflight failure
    # instead of a bad capture.
    route = run(['route', '-n', 'get', 'default']).stdout
    got = [l.split(':', 1)[1].strip() for l in route.splitlines()
           if l.strip().startswith('interface:')]
    if got != [TARGET_IFACE]:
        raise RuntimeError('default route is on %r, not %s: with the USB NIC '
                           'disabled the peer must be reached through the NIC '
                           'under test' % (got, TARGET_IFACE))
    peer = run(['route', '-n', 'get', PEER[0]]).stdout
    pgot = [l.split(':', 1)[1].strip() for l in peer.splitlines()
            if l.strip().startswith('interface:')]
    if pgot != [TARGET_IFACE]:
        raise RuntimeError('the peer route is on %r, not %s'
                           % (pgot, TARGET_IFACE))
    return '%s via %s; peer via %s' % (MGMT_ADDR, MGMT_IFACE, TARGET_IFACE)


def target_iface():
    out = run(['ifconfig', TARGET_IFACE]).stdout
    m = re.search(r'inet (\S+)', out)
    if not m:
        raise RuntimeError('%s has no IPv4: the target NIC is the peer-facing one'
                           % TARGET_IFACE)
    return '%s = %s' % (TARGET_IFACE, m.group(1))


def daemon():
    p = pathlib.Path(DAEMON)
    if not p.is_file():
        raise RuntimeError('%s missing: run tools/abi/deploy.py' % DAEMON)
    d = plistlib.loads(p.read_bytes())
    label = d.get('Label', '')
    if label != 'org.example.round21load':
        raise RuntimeError('Label is %r but the file is org.example.round21load.plist: '
                           'launchd refuses to bootstrap this' % label)
    args = d.get('ProgramArguments', [])
    joined = ' '.join(args)
    # Round23: the job runs tools/abi/round23-load.sh, which waits for the target
    # NIC and then execs load.py with the load directory. Accept either form, but
    # when the argument is the wrapper, require the wrapper to exist AND to name
    # this round's load.py -- so "the daemon runs a script that no longer exists"
    # and "the daemon runs last round's loader" both still fail here.
    if 'tools/abi/load.py' in joined:
        if LOAD_DIR not in joined:
            raise RuntimeError('ProgramArguments do not name the load dir: %r'
                               % (args,))
    elif 'tools/abi/round23-load.sh' in joined:
        wrapper = pathlib.Path('/Users/ling/r12work/tools/abi/round23-load.sh')
        if not wrapper.is_file():
            raise RuntimeError('%s is named by the daemon but does not exist'
                               % wrapper)
        wtext = wrapper.read_text(encoding='utf-8', errors='replace')
        if 'tools/abi/load.py' not in wtext:
            raise RuntimeError('%s does not run tools/abi/load.py' % wrapper)
        if LOAD_DIR not in wtext:
            raise RuntimeError('%s does not default to %s' % (wrapper, LOAD_DIR))
    else:
        raise RuntimeError('ProgramArguments still point at another round: %r'
                           % (args,))
    out = d.get('StandardOutPath', '')
    if LOAD_DIR not in out:
        raise RuntimeError('StandardOutPath %r is outside the load dir' % out)
    return 'label+paths ok, RunAtLoad=%s' % d.get('RunAtLoad')


def load_inputs():
    d = pathlib.Path(LOAD_DIR)
    if not d.is_dir():
        raise RuntimeError('%s missing' % LOAD_DIR)
    for name in ('token.txt', 'batch.txt'):
        f = d / name
        if not f.is_file():
            raise RuntimeError('%s missing: deploy.py writes it' % f)
        if not os.access(f, os.W_OK):
            raise RuntimeError('%s is not writable by %s (owner=%s): %s'
                               % (f, os.environ.get('USER', 'you'),
                                  f.stat().st_uid, 'sudo chown -R $USER ' + LOAD_DIR))
    token = (d / 'token.txt').read_text().strip()
    batch = (d / 'batch.txt').read_text().strip()
    if not re.fullmatch(r'0x[0-9a-fA-F]{8}', token):
        raise RuntimeError('token.txt is %r, not 0x%08x form' % (token, 0))
    if not batch.isdigit() or int(batch) != len(REQUESTS):
        raise RuntimeError('batch.txt is %r; current load requires %d' %
                           (batch, len(REQUESTS)))
    return 'token=%s batch=%s' % (token, batch)


def peer_reachable():
    host, port = PEER
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        # The seed is exactly 1024 zero bytes; the peer echoes it before any
        # request. This proves BOTH that the process lives and that the path is
        # not blocked, which is what `acked=0` cannot distinguish.
        s.sendto(bytes(1024), PEER)
        data, _ = s.recvfrom(2048)
        if len(data) != 1024:
            raise RuntimeError('peer answered %d bytes, expected the 1024 B seed'
                               % len(data))
    except socket.timeout:
        raise RuntimeError(
            'no UDP echo from %s:%d. Start the peer AND open the firewall:\n'
            '    start: tools/abi/peer.py --log ... --run-token 0x... --port %d\n'
            '    firewall (Windows, elevated):\n'
            '        netsh advfirewall firewall add rule name=%s '
            'dir=in action=allow protocol=UDP localport=%d profile=any\n'
            '  a closed port is indistinguishable from a TX fault in the '
            'artifact, so this must be green before a run counts.\n'
            '  NOTE: `netsh ... add rule` rejects a `description=` argument and '
            'fails silently (LastExit 1, no rule created).'
            % (host, port, port, PEER_RULE, port))
    finally:
        s.close()
    return 'seed round-tripped'


def _bundle_version(path):
    info = pathlib.Path(path) / 'Contents/Info.plist'
    return plistlib.loads(info.read_bytes())['CFBundleVersion']


def _build_versions():
    return {'RTL812xLucy': _bundle_version(ROOT / 'build-lucy/RTL812xLucy.kext'),
            'AMDMapperProbe': _bundle_version(ROOT / 'build-m1a/AMDMapperProbe.kext')}


def kexts():
    """Installed bytes must be the ones this tree just built.

    Round 22: the old check printed whatever `kmutil showloaded` said and
    reported "ok" regardless, so a stale /Library/Extensions passed while the
    docstring claimed it was checking for exactly that. It now compares the
    INSTALLED bundle (what the next boot will load) against the build output,
    and that is a hard failure.
    """
    want = _build_versions()
    got = {}
    for name in want:
        target = pathlib.Path('/Library/Extensions') / (name + '.kext')
        if not (target / 'Contents/Info.plist').is_file():
            raise RuntimeError('%s is not installed' % name)
        got[name] = _bundle_version(target)
    stale = {k: (got[k], want[k]) for k in want if got[k] != want[k]}
    if stale:
        raise RuntimeError('installed kext differs from this build: %r' % (stale,))
    return 'installed %r' % (got,)


def kexts_loaded():
    """The RUNNING kexts must be the installed ones (checked after the reboot).

    Before a reboot this is legitimately stale: the new kexts are on disk but
    the old ones are still in memory. Deploy tolerates this one check for that
    reason; capture does not, because by then a mismatch means the run measured
    a different build than the one being reported.
    """
    want = _build_versions()
    out = run(['kmutil', 'showloaded', '--list-only']).stdout
    got = {}
    for line in out.splitlines():
        for name in want:
            if name in line:
                m = re.search(re.escape(name) + r'\s+(\S+)\s', line)
                if m:
                    # `kmutil showloaded --list-only` prints the version in
                    # parentheses; the first draft kept them and would have
                    # compared "(1.1.205)" against "1.1.206" even after a
                    # correct reboot.
                    got[name] = m.group(1).strip('()')
    if not got:
        raise RuntimeError('neither kext is loaded')
    stale = {k: (got.get(k), want[k]) for k in want if got.get(k) != want[k]}
    if stale:
        raise RuntimeError('loaded kext differs from this build: %r' % (stale,))
    return 'loaded %r' % (got,)


def main():
    check('efi', efi)
    check('mgmt-route', mgmt_route)
    check('target-iface', target_iface)
    check('load-daemon', daemon)
    check('load-inputs', load_inputs)
    check('peer', peer_reachable)
    check('kexts', kexts)
    check('kexts-loaded', kexts_loaded)

    for name, detail in ok:
        print('  ok   %-14s %s' % (name, detail))
    for name, detail in bad:
        print('  FAIL %-14s %s' % (name, detail))
    if bad:
        print('\n%d check(s) failed: a run now would produce an ambiguous result.'
              % len(bad))
        return 1
    print('\npreflight green: a run now measures the driver, not the environment.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
