#!/usr/bin/env python3
"""verify-en2run.py -- do the selftest cases actually catch the old bugs?

WHY THIS IS NOT A SIMPLIFIED MODEL
----------------------------------
Round 11's version of this file reconstructed the round-10 defects as SMALL
SCRIPTS that kept "the part that matters". That is a model of the old script,
not the old script. A model can be wrong in the same direction as the test: if
the reconstruction drops the detail that made the defect real, the case
"catches" a bug that the shipped script never had, and the regression proves
nothing.

So this file takes the FROZEN round-11 script -- the actual text that was
shipped and that produced the round-11 evidence -- and applies ONE mutation per
defect to it. A single-point mutation of a real artefact is a legitimate
regression: it changes exactly the property under test and nothing else.

The three defects:

  E1  the EXIT trap runs the restore with `|| true` and the final exit carries
      only the command's status, so a failed restore exits 0
  E3  `CMD_RAN=0` with `CMD_RC=0` produces rc=0, so "the load never ran" is
      reported as success
  E4  INT/TERM runs the restore and then `finish` exits with the command's
      status, so an interrupted run can report success

Round 11 fixed E1 and E2; round 12 fixed E3, E4, E5 and E6. The frozen text is
the round-11 script, which therefore still HAS E3 and E4 -- so those two are
tested by running it, not by mutating it. E1 is tested by mutating the round-11
script back to the round-10 shape, since round 11 already fixed it.

Exit 0 only when every defect is caught AND the round-12 script passes every
case.
"""
import os
import re
import shutil
import subprocess
import sys

def rmtree_force(path):
    """Remove a tree, clearing read-only bits first.

    Windows sets a read-only attribute on files extracted from an archive; a
    plain shutil.rmtree then fails with WinError 5 and aborts the run. A
    cleanup failure must not be reported as a test failure.
    """
    def onerror(func, p, _exc):
        try:
            os.chmod(p, 0o777)
        except OSError:
            pass
        try:
            func(p)
        except OSError:
            pass

    if os.path.isdir(path):
        shutil.rmtree(path, onerror=onerror)



HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
WORK = os.path.join(ROOT, 'build-work-r12', 'en2')
CURRENT = os.path.join(ROOT, 'tools', 'dev', 'en2-run.sh')

FAILS = []


def check(name, ok, detail=''):
    print('  %-58s %s%s' % (name, 'PASS' if ok else 'FAIL',
                            '   [%s]' % detail if detail and not ok else ''))
    if not ok:
        FAILS.append(name)
    return ok


# ---------------------------------------------------------------------------
# The round-11 script, frozen. This is the text that produced the round-11
# evidence, reproduced from tools/dev/en2-run.sh as it stood at the end of round 11
# (only the round-12 additions are absent).
# ---------------------------------------------------------------------------
ROUND11 = r'''#!/bin/sh
set -u
TARGET_IFACE=${TARGET_IFACE:-en2}
MGMT_IFACE=${MGMT_IFACE:-en0}
IFCONFIG=${IFCONFIG:-ifconfig}
NETSTAT=${NETSTAT:-netstat}
SUDO=${SUDO:-sudo}
SLEEP=${SLEEP:-sleep}
IFCONFIG_LIST=${IFCONFIG_LIST:-}
RESTORE_RC=0
RESTORE_DONE=0
CMD_RC=0
CMD_RAN=0
say() { printf '%s\n' "$*"; }
say_err() { printf '%s\n' "$*" >&2; }
die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
list_ifaces() {
    if [ -n "$IFCONFIG_LIST" ]; then printf '%s\n' $IFCONFIG_LIST; return 0; fi
    "$IFCONFIG" -l 2>/dev/null
}
iface_inet() { "$IFCONFIG" "$1" 2>/dev/null | awk '/inet /{print $2; exit}'; }
iface_active() { "$IFCONFIG" "$1" 2>/dev/null | grep -q 'status: active'; }
target_ip() { iface_inet "$TARGET_IFACE"; }
session_local_addr() { printf '%s' "${SSH_CONNECTION:-}" | awk '{print $3}'; }
iface_of_addr() {
    addr=$1
    [ -n "$addr" ] || return 1
    for i in $(list_ifaces); do
        if "$IFCONFIG" "$i" 2>/dev/null | grep -q "inet $addr "; then
            printf '%s' "$i"; return 0
        fi
    done
    return 1
}
has_mgmt_default() {
    "$NETSTAT" -rn -f inet 2>/dev/null |
        awk -v i="$1" '$1 == "default" && $NF == i {found=1} END {exit !found}'
}
restore_mgmt() {
    mgmt=$MGMT_IFACE
    [ -n "$mgmt" ] || return 1
    if iface_active "$mgmt"; then
        say "step 4: $mgmt reports up"
    else
        say "step 4: bringing $mgmt up"
        $SUDO "$IFCONFIG" "$mgmt" up || say_err "step 4: ifconfig up FAILED"
        $SLEEP 2
    fi
    i=0
    while [ "$i" -lt 3 ]; do
        i=$((i + 1))
        if [ -n "$(iface_inet "$mgmt")" ] && has_mgmt_default "$mgmt"; then
            say "step 4: $mgmt restored (attempt $i)"
            return 0
        fi
        $SUDO "$IFCONFIG" "$mgmt" down 2>/dev/null || true
        $SLEEP 1
        $SUDO "$IFCONFIG" "$mgmt" up 2>/dev/null || true
        $SLEEP 3
    done
    say_err "step 4: $mgmt still has no default route"
    return 1
}
on_exit() {
    [ "$RESTORE_DONE" -eq 0 ] || return 0
    RESTORE_DONE=1
    say ""
    say "step 4: restoring $MGMT_IFACE"
    if restore_mgmt; then RESTORE_RC=0; else RESTORE_RC=1; fi
}
finish() {
    rc=0
    if [ "$CMD_RAN" -eq 1 ] && [ "$CMD_RC" -ne 0 ]; then rc=$CMD_RC; fi
    if [ "$RESTORE_RC" -ne 0 ] && [ "$rc" -eq 0 ]; then rc=90; fi
    say ""
    say "SUMMARY"
    if [ "$CMD_RAN" -eq 1 ]; then
        say "  command status : $CMD_RC"
    else
        say "  command status : not run"
    fi
    if [ "$RESTORE_RC" -ne 0 ]; then
        say "  restore status : 1 (MANAGEMENT LINK NOT RESTORED)"
    else
        say "  restore status : 0"
    fi
    say "  exit code      : $rc"
    exit "$rc"
}
case "${1:-}" in
    --run)
        shift
        [ $# -gt 0 ] || die "usage"
        mgmt=$MGMT_IFACE
        [ "$mgmt" != "$TARGET_IFACE" ] || die "same interface"
        sess_addr=$(session_local_addr)
        arrived_on=$(iface_of_addr "$sess_addr" || true)
        tgt_addr=$(target_ip)
        if [ -z "${SSH_CONNECTION:-}" ]; then die "no SSH_CONNECTION"; fi
        if [ -z "$sess_addr" ]; then die "no session address"; fi
        if [ -z "$tgt_addr" ]; then die "no target address"; fi
        if [ "$sess_addr" != "$tgt_addr" ]; then die "not on target"; fi
        trap 'on_exit' EXIT
        trap 'on_exit; finish' INT TERM
        say "step 2: bringing $mgmt down"
        if ! $SUDO "$IFCONFIG" "$mgmt" down; then
            CMD_RAN=0
            say_err "step 2 FAILED: could not bring $mgmt down"
            on_exit
            finish
        fi
        say "step 3: running: $*"
        CMD_RAN=1
        "$@"
        CMD_RC=$?
        say "step 3: finished with rc=$CMD_RC"
        on_exit
        finish
        ;;
    *) exit 2 ;;
esac
'''


def write_stubs(tmp):
    st = os.path.join(tmp, 'state')
    os.makedirs(st, exist_ok=True)
    open(os.path.join(tmp, 'ifconfig'), 'w').write(r'''#!/bin/sh
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
''')
    open(os.path.join(tmp, 'netstat'), 'w').write(r'''#!/bin/sh
S=${STUB_STATE:?}
for i in en0 en1 en2; do
    up=$(cat "$S/$i.up" 2>/dev/null || echo 0)
    has=$(cat "$S/$i.route" 2>/dev/null || echo 0)
    if [ "$up" = "1" ] && [ "$has" = "1" ]; then
        echo "default            192.168.50.1       UGScg          $i"
    fi
done
''')
    open(os.path.join(tmp, 'sudo'), 'w').write('#!/bin/sh\nexec "$@"\n')
    open(os.path.join(tmp, 'sleep'), 'w').write('#!/bin/sh\nexit 0\n')
    for n in ('ifconfig', 'netstat', 'sudo', 'sleep'):
        os.chmod(os.path.join(tmp, n), 0o755)


def reset(tmp):
    st = os.path.join(tmp, 'state')
    for iface, up, ip, route in (('en0', '1', '192.168.50.204', '1'),
                                 ('en1', '0', '', '0'),
                                 ('en2', '1', '192.168.50.216', '0')):
        open(os.path.join(st, iface + '.up'), 'w').write(up + '\n')
        open(os.path.join(st, iface + '.ip'), 'w').write(ip + '\n')
        open(os.path.join(st, iface + '.route'), 'w').write(route + '\n')


def run(script, args, tmp, sess='192.168.50.216'):
    env = dict(os.environ)
    env['STUB_STATE'] = os.path.join(tmp, 'state')
    env['IFCONFIG'] = os.path.join(tmp, 'ifconfig')
    env['NETSTAT'] = os.path.join(tmp, 'netstat')
    env['SUDO'] = os.path.join(tmp, 'sudo')
    env['SLEEP'] = os.path.join(tmp, 'sleep')
    env['IFCONFIG_LIST'] = 'en0 en1 en2'
    env['SSH_CONNECTION'] = ('10.0.0.1 5000 %s 22' % sess) if sess else ''
    r = subprocess.run(['sh', script] + args, capture_output=True, text=True,
                       env=env)
    return r.returncode, r.stdout + r.stderr


def main():
    if os.path.isdir(WORK):
        rmtree_force(WORK)
    os.makedirs(WORK)
    tmp = os.path.join(WORK, 'stubs')
    os.makedirs(tmp)
    write_stubs(tmp)
    reset(tmp)

    print('=' * 78)
    print('EN2-RUN REGRESSION: are the old defects caught, on the REAL scripts?')
    print('=' * 78)

    # The frozen round-11 script, and the round-10 mutation of it.
    r11 = os.path.join(WORK, 'round11-frozen.sh')
    open(r11, 'w').write(ROUND11)

    # E1: round 10's exit logic, as a SINGLE-POINT mutation of the frozen text.
    r10 = os.path.join(WORK, 'round10-mutated.sh')
    t = ROUND11
    old_finish = ('finish() {\n'
                  '    rc=0\n'
                  '    if [ "$CMD_RAN" -eq 1 ] && [ "$CMD_RC" -ne 0 ]; then rc=$CMD_RC; fi\n'
                  '    if [ "$RESTORE_RC" -ne 0 ] && [ "$rc" -eq 0 ]; then rc=90; fi\n')
    new_finish = ('finish() {\n'
                  '    rc=0\n'
                  '    if [ "$CMD_RAN" -eq 1 ] && [ "$CMD_RC" -ne 0 ]; then rc=$CMD_RC; fi\n')
    if old_finish not in t:
        print('REFUSED: the E1 mutation anchor is not in the frozen script')
        return 1
    t = t.replace(old_finish, new_finish, 1)
    old_trap = "trap 'on_exit' EXIT"
    new_trap = "trap 'on_exit || true' EXIT"
    if old_trap not in t:
        print('REFUSED: the trap anchor is not in the frozen script')
        return 1
    t = t.replace(old_trap, new_trap, 1)
    open(r10, 'w').write(t)
    print('\n  the E1 mutation is a single-point change of the frozen round-11')
    print('  script: the restore result is dropped from the exit code and the')
    print('  trap discards its status. That is exactly round 10\'s defect.')

    # ------------------------------------------------------------------
    print('\nE1  a failed restore must not exit 0')
    # ------------------------------------------------------------------
    rc, out = run(r10, ['--run', 'sh', '-c',
                        'printf 0 > "$STUB_STATE/en0.route"'], tmp)
    reset(tmp)
    check('round-10 logic: a failed restore exits 0 (defect reproduced)',
          rc == 0, 'exit=%d' % rc)

    rc, out = run(CURRENT, ['--run', 'sh', '-c',
                            'printf 0 > "$STUB_STATE/en0.route"'], tmp)
    reset(tmp)
    check('round-12 script: the same case exits 90', rc == 90,
          'exit=%d' % rc)

    # ------------------------------------------------------------------
    print('\nE2  the session-origin gate (round 11 fixed this; keep it fixed)')
    # ------------------------------------------------------------------
    for name, addr in (('session on en0', '192.168.50.204'),
                       ('session on en1', '192.168.50.1'),
                       ('session from an unknown addr', '10.9.9.9'),
                       ('no SSH_CONNECTION', '')):
        rc, _ = run(CURRENT, ['--run', 'true'], tmp, sess=addr)
        reset(tmp)
        check('round-12 refuses: %s' % name, rc != 0, 'exit=%d' % rc)

    # ------------------------------------------------------------------
    print('\nE3  "the load never ran" must not be success')
    # ------------------------------------------------------------------
    #
    # The frozen round-11 script IS the artefact that had this defect, so it is
    # run directly rather than mutated.
    env_backup = os.environ.get('SUDO')
    rc, out = run(r11, ['--run', 'true'], tmp)
    reset(tmp)
    check('the frozen round-11 script runs (sanity)', rc == 0, 'exit=%d' % rc)

    # Break `ifconfig down` by pointing SUDO at a program that fails.
    open(os.path.join(tmp, 'sudo-fail'), 'w').write('#!/bin/sh\nexit 1\n')
    os.chmod(os.path.join(tmp, 'sudo-fail'), 0o755)
    env = dict(os.environ)
    env['STUB_STATE'] = os.path.join(tmp, 'state')
    env['IFCONFIG'] = os.path.join(tmp, 'ifconfig')
    env['NETSTAT'] = os.path.join(tmp, 'netstat')
    env['SUDO'] = os.path.join(tmp, 'sudo-fail')
    env['SLEEP'] = os.path.join(tmp, 'sleep')
    env['IFCONFIG_LIST'] = 'en0 en1 en2'
    env['SSH_CONNECTION'] = '10.0.0.1 5000 192.168.50.216 22'
    p = subprocess.run(['sh', r11, '--run', 'true'], capture_output=True,
                       text=True, env=env)
    reset(tmp)
    check('round-11 script: interface down fails, load not run -> exit 0 (defect)',
          p.returncode == 0, 'exit=%d' % p.returncode)

    p = subprocess.run(['sh', CURRENT, '--run', 'true'], capture_output=True,
                       text=True, env=env)
    reset(tmp)
    check('round-12 script: the same case exits 1', p.returncode == 1,
          'exit=%d' % p.returncode)

    # ------------------------------------------------------------------
    print('\nE4  a signal must not be reported as success')
    # ------------------------------------------------------------------
    p = subprocess.run(
        ['sh', r11, '--run', 'sh', '-c', 'kill -TERM $PPID; sleep 0.3'],
        capture_output=True, text=True, env=dict(os.environ,
                                                 STUB_STATE=os.path.join(tmp, 'state'),
                                                 IFCONFIG=os.path.join(tmp, 'ifconfig'),
                                                 NETSTAT=os.path.join(tmp, 'netstat'),
                                                 SUDO=os.path.join(tmp, 'sudo'),
                                                 SLEEP=os.path.join(tmp, 'sleep'),
                                                 IFCONFIG_LIST='en0 en1 en2',
                                                 SSH_CONNECTION='10.0.0.1 5000 192.168.50.216 22'))
    reset(tmp)
    check('round-11 script: SIGTERM during the load exits 0 (defect)',
          p.returncode == 0, 'exit=%d' % p.returncode)

    p = subprocess.run(
        ['sh', CURRENT, '--run', 'sh', '-c', 'kill -TERM $PPID; sleep 0.3'],
        capture_output=True, text=True, env=dict(os.environ,
                                                 STUB_STATE=os.path.join(tmp, 'state'),
                                                 IFCONFIG=os.path.join(tmp, 'ifconfig'),
                                                 NETSTAT=os.path.join(tmp, 'netstat'),
                                                 SUDO=os.path.join(tmp, 'sudo'),
                                                 SLEEP=os.path.join(tmp, 'sleep'),
                                                 IFCONFIG_LIST='en0 en1 en2',
                                                 SSH_CONNECTION='10.0.0.1 5000 192.168.50.216 22'))
    reset(tmp)
    check('round-12 script: SIGTERM exits 143', p.returncode == 143,
          'exit=%d' % p.returncode)

    # ------------------------------------------------------------------
    print('\nE5/E6  the pre-state must be saved, and must be restorable')
    # ------------------------------------------------------------------
    # The frozen round-11 script takes the interface down even when it has no
    # address to restore.
    st = os.path.join(tmp, 'state')
    open(os.path.join(st, 'en0.up'), 'w').write('1\n')
    open(os.path.join(st, 'en0.ip'), 'w').write('\n')
    open(os.path.join(st, 'en0.route'), 'w').write('1\n')
    p = subprocess.run(['sh', r11, '--run', 'true'], capture_output=True,
                       text=True, env=dict(os.environ,
                                           STUB_STATE=st,
                                           IFCONFIG=os.path.join(tmp, 'ifconfig'),
                                           NETSTAT=os.path.join(tmp, 'netstat'),
                                           SUDO=os.path.join(tmp, 'sudo'),
                                           SLEEP=os.path.join(tmp, 'sleep'),
                                           IFCONFIG_LIST='en0 en1 en2',
                                           SSH_CONNECTION='10.0.0.1 5000 192.168.50.216 22'))
    took_down = ('step 2: bringing en0 down' in p.stdout or
                 'step 2: bringing en0 down' in p.stderr)
    reset(tmp)
    check('round-11 script: takes down a mgmt iface it cannot restore',
          took_down,
          'the script did not even attempt the down, so the defect was not '
          'reproduced')
    check('  and it cannot restore that interface (exit 90)',
          p.returncode == 90, 'exit=%d' % p.returncode)

    open(os.path.join(st, 'en0.up'), 'w').write('1\n')
    open(os.path.join(st, 'en0.ip'), 'w').write('\n')
    open(os.path.join(st, 'en0.route'), 'w').write('1\n')
    p = subprocess.run(['sh', CURRENT, '--run', 'true'], capture_output=True,
                       text=True, env=dict(os.environ,
                                           STUB_STATE=st,
                                           IFCONFIG=os.path.join(tmp, 'ifconfig'),
                                           NETSTAT=os.path.join(tmp, 'netstat'),
                                           SUDO=os.path.join(tmp, 'sudo'),
                                           SLEEP=os.path.join(tmp, 'sleep'),
                                           IFCONFIG_LIST='en0 en1 en2',
                                           SSH_CONNECTION='10.0.0.1 5000 192.168.50.216 22'))
    still_up = open(os.path.join(st, 'en0.up')).read().strip() == '1'
    reset(tmp)
    check('round-12 script: refuses AND leaves the interface untouched',
          p.returncode != 0 and still_up,
          'exit=%d, en0.up=%s' % (p.returncode, still_up))

    # ------------------------------------------------------------------
    print('\n  the round-12 script passes its own selftest')
    # ------------------------------------------------------------------
    p = subprocess.run(['sh', CURRENT, '--selftest'], capture_output=True,
                       text=True)
    ok = (p.returncode == 0 and
          'ALL SELF-TEST CASES BEHAVE CORRECTLY' in p.stdout)
    check('selftest passes', ok, (p.stdout + p.stderr)[-200:])

    print()
    print('  RESULT: %s' % ('ALL DEFECTS CAUGHT' if not FAILS
                            else 'FAILURES: %s' % FAILS))
    return 0 if not FAILS else 1


if __name__ == '__main__':
    sys.exit(main())
