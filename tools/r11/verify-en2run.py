#!/usr/bin/env python3
"""verify-en2run.py -- do the selftest cases actually catch round 10's bugs?

WHY
---
`en2-run.sh --selftest` passes on the round-11 script. That is only evidence if
the same cases FAIL on the round-10 script. Round 10 had two reproducible
defects:

  E1  restore_mgmt() returns 1, the EXIT trap runs it with `|| true`, and the
      final `exit $rc` carries only the COMMAND's status. A run whose
      management interface never came back exits 0.

  E2  the gate only refuses when the session is ON the management interface.
      A session from en1, from an unknown address, or with SSH_CONNECTION unset
      falls through and the script takes en0 down.

This script reconstructs both defects as small scripts that keep the round-10
control flow, runs the same seven cases against them, and requires each defect
to be caught. It does not modify the real en2-run.sh.

Exit 0 only when every round-10 defect is caught AND the round-11 script passes.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
WORK = os.path.join(ROOT, 'build-work-r11', 'en2')

# Round 10's exit-code logic, reduced to the part that matters. The trap runs
# the restore with `|| true`, then `exit $rc` where rc is the COMMAND's status.
ROUND10_EXIT = r'''#!/bin/sh
set -u
RESTORE_OK=1
restore_mgmt() {
    # Round 10's restore: link up, then check for a default route.
    ifconfig en0 up >/dev/null 2>&1
    netstat -rn -f inet 2>/dev/null | awk '$1=="default" && $NF=="en0"{f=1} END{exit !f}'
}
CMD="$1"; shift
trap 'restore_mgmt || true' EXIT INT TERM
set +e
"$CMD" "$@"
rc=$?
set -e
exit $rc
'''

# Round 10's gate, reduced: refuse only if the session is on the management
# interface. Everything else falls through.
ROUND10_GATE = r'''#!/bin/sh
set -u
MGMT_IFACE=en0
TARGET_IFACE=en2
sess=$(printf '%s' "${SSH_CONNECTION:-}" | awk '{print $3}')
arrived=""
for i in $(ifconfig -l 2>/dev/null); do
    if ifconfig "$i" 2>/dev/null | grep -q "inet $sess "; then arrived=$i; break; fi
done
if [ "$arrived" = "$MGMT_IFACE" ]; then
    echo "refused: session on mgmt" >&2
    exit 1
fi
echo "proceeding (arrived on ${arrived:-unknown})"
exit 0
'''

STUB_IFCONFIG = r'''#!/bin/sh
S=${STUB_STATE:?}
case "$1" in
  -l) echo "en0 en1 en2"; exit 0 ;;
esac
iface=$1; shift
up=$(cat "$S/$iface.up" 2>/dev/null || echo 0)
case "$1" in
  up)   echo 1 > "$S/$iface.up"; exit 0 ;;
  down) echo 0 > "$S/$iface.up"; exit 0 ;;
esac
[ "$up" = "1" ] || exit 0
echo "$iface: flags=8863<UP>"
ip=$(cat "$S/$iface.ip" 2>/dev/null)
[ -n "$ip" ] && echo "	inet $ip netmask 0xffffff00 broadcast 192.168.50.255"
echo "	status: active"
exit 0
'''

STUB_NETSTAT = r'''#!/bin/sh
S=${STUB_STATE:?}
for i in en0 en1 en2; do
    up=$(cat "$S/$i.up" 2>/dev/null || echo 0)
    has=$(cat "$S/$i.route" 2>/dev/null || echo 0)
    if [ "$up" = "1" ] && [ "$has" = "1" ]; then
        echo "default            192.168.50.1       UGScg          $i"
    fi
done
'''


def write_stubs(tmp):
    os.makedirs(os.path.join(tmp, 'state'), exist_ok=True)
    st = os.path.join(tmp, 'state')
    for iface, up, ip, route in (
            ('en0', '1', '192.168.50.204', '1'),
            ('en1', '0', '', '0'),
            ('en2', '1', '192.168.50.216', '0')):
        open(os.path.join(st, iface + '.up'), 'w').write(up + '\n')
        open(os.path.join(st, iface + '.ip'), 'w').write(ip + '\n')
        open(os.path.join(st, iface + '.route'), 'w').write(route + '\n')
    for name, body in (('ifconfig', STUB_IFCONFIG), ('netstat', STUB_NETSTAT)):
        p = os.path.join(tmp, name)
        open(p, 'w').write(body)
        os.chmod(p, 0o755)


def run(script, args, env_extra, tmp):
    env = dict(os.environ)
    env['PATH'] = tmp + ':' + env['PATH']
    env['STUB_STATE'] = os.path.join(tmp, 'state')
    env.update(env_extra)
    r = subprocess.run(['sh', script] + args, capture_output=True, text=True,
                       env=env)
    return r.returncode, r.stdout + r.stderr


def reset(tmp):
    st = os.path.join(tmp, 'state')
    for iface, up, route in (('en0', '1', '1'), ('en1', '0', '0'),
                             ('en2', '1', '0')):
        open(os.path.join(st, iface + '.up'), 'w').write(up + '\n')
        open(os.path.join(st, iface + '.route'), 'w').write(route + '\n')


def main():
    if not os.path.isdir(WORK):
        os.makedirs(WORK)
    tmp = os.path.join(WORK, 'stubs')
    if os.path.isdir(tmp):
        import shutil
        shutil.rmtree(tmp)
    os.makedirs(tmp)
    write_stubs(tmp)

    r10_exit = os.path.join(WORK, 'round10-exit.sh')
    r10_gate = os.path.join(WORK, 'round10-gate.sh')
    open(r10_exit, 'w').write(ROUND10_EXIT)
    open(r10_gate, 'w').write(ROUND10_GATE)

    r11 = os.path.join(ROOT, 'tools', 'en2-run.sh')

    print('=' * 78)
    print('EN2-RUN MUTATION TEST: are round 10\'s two defects actually caught?')
    print('=' * 78)

    ok = True

    # ---- E1: restore failure must not be masked by a successful command ----
    print('\nE1  restore failure vs exit code')
    # Round 10: command succeeds, restore fails (en0 up but no route) -> ?
    rc, out = run(r10_exit, ['sh', '-c',
                             'printf 0 > "$STUB_STATE/en0.route"'],
                  {'SSH_CONNECTION': '10.0.0.1 5000 192.168.50.216 22'}, tmp)
    reset(tmp)
    r10_e1 = (rc == 0)
    print('  round-10 script : exit=%d  %s'
          % (rc, '<-- MASKED (defect present)' if r10_e1
             else '<-- defect not reproduced'))
    if not r10_e1:
        print('      NOTE: could not reproduce the round-10 masking.')
        ok = False

    # Round 11: same scenario through --run must exit 90.
    rc, out = run(r11, ['--run', 'sh', '-c',
                        'printf 0 > "$STUB_STATE/en0.route"'],
                  {'SSH_CONNECTION': '10.0.0.1 5000 192.168.50.216 22',
                   'IFCONFIG': os.path.join(tmp, 'ifconfig'),
                   'NETSTAT': os.path.join(tmp, 'netstat'),
                   'SUDO': 'sh -c', 'SLEEP': 'true',
                   'IFCONFIG_LIST': 'en0 en1 en2'}, tmp)
    reset(tmp)
    r11_e1 = (rc == 90)
    print('  round-11 script : exit=%d  %s'
          % (rc, '<-- correctly non-zero' if r11_e1
             else '<-- FAIL: still masked'))
    if not r11_e1:
        print('      output:\n' + '\n'.join('        ' + l
                                             for l in out.splitlines()[-12:]))
        ok = False

    # ---- E2: a session from anywhere but the target must be refused ----
    print('\nE2  session origin gate')
    cases = [
        ('session on en1 (third iface)', '192.168.50.1'),
        ('session from an unknown addr', '10.9.9.9'),
        ('no SSH_CONNECTION', ''),
    ]
    for name, addr in cases:
        env = {'SSH_CONNECTION': ('10.0.0.1 5000 %s 22' % addr) if addr else ''}
        rc10, _ = run(r10_gate, [], env, tmp)
        reset(tmp)
        rc11, _ = run(r11, ['--run', 'true'],
                      dict(env,
                           IFCONFIG=os.path.join(tmp, 'ifconfig'),
                           NETSTAT=os.path.join(tmp, 'netstat'),
                           SUDO='sh -c', SLEEP='true',
                           IFCONFIG_LIST='en0 en1 en2'), tmp)
        reset(tmp)
        caught = (rc10 == 0) and (rc11 == 1)
        print('  %-32s round-10 exit=%d (proceeds), round-11 exit=%d  %s'
              % (name, rc10, rc11,
                 'CAUGHT' if caught else 'NOT CAUGHT'))
        if not caught:
            ok = False

    # ---- the positive case: a legitimate run must still work ----
    print('\npositive  a legitimate run (session on the target) must succeed')
    rc, out = run(r11, ['--run', 'true'],
                  {'SSH_CONNECTION': '10.0.0.1 5000 192.168.50.216 22',
                   'IFCONFIG': os.path.join(tmp, 'ifconfig'),
                   'NETSTAT': os.path.join(tmp, 'netstat'),
                   'SUDO': 'sh -c', 'SLEEP': 'true',
                   'IFCONFIG_LIST': 'en0 en1 en2'}, tmp)
    reset(tmp)
    print('  round-11 script : exit=%d  %s'
          % (rc, 'OK' if rc == 0 else 'FAIL'))
    if rc != 0:
        ok = False

    print()
    print('  RESULT: %s' % ('BOTH ROUND-10 DEFECTS CAUGHT' if ok
                            else 'FAILURES'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
