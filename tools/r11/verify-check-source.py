#!/usr/bin/env python3
"""verify-check-source.py -- the relaxed guard must still catch real violations.

WHY
---
tools/check_source.py was relaxed in round 11 so that read-only uses of
`nvram boot-args` and `kmutil showloaded` no longer fail the hygiene gate. A
relaxation that stops catching anything is not a fix, it is a disabled check.

So this script plants each violation in a temporary copy of the tree and
requires check_source.py to reject it, and also confirms that the legitimate
read-only forms are accepted.
"""
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
WORK = os.path.join(ROOT, 'build-work-r11', 'checksource')


def run(tree):
    r = subprocess.run([sys.executable, os.path.join(tree, 'tools',
                                                    'check_source.py')],
                       capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr).strip()


def plant(tree, name, body):
    p = os.path.join(tree, 'tools', name)
    open(p, 'w').write('#!/bin/sh\n' + body + '\n')


def main():
    if os.path.isdir(WORK):
        shutil.rmtree(WORK)
    os.makedirs(WORK)

    print('=' * 78)
    print('CHECK_SOURCE: does the scoped guard still catch real violations?')
    print('=' * 78)

    # Baseline: a copy of the real tree must pass.
    base = os.path.join(WORK, 'base')
    shutil.copytree(ROOT, base, ignore=shutil.ignore_patterns(
        'build-work-r11', 'build-m1a', 'test-work*', '*.pyc', '__pycache__'))
    rc, out = run(base)
    print('  baseline copy            : exit=%d %s'
          % (rc, out.splitlines()[-1] if out else ''))
    if rc != 0:
        print('  REFUSED: the unmodified tree already fails')
        return 1

    ok = True

    # ---- violations that MUST be caught ----
    bad_cases = [
        ('offline-nvram-write.sh', 'nvram boot-args="-v keepsyms=1"',
         'nvram write in an offline script'),
        ('offline-kmutil-load.sh', 'kmutil load -p /Library/Extensions/X.kext',
         'kmutil load in an offline script'),
        ('offline-kextload.sh', 'kextload /Library/Extensions/X.kext',
         'kextload in an offline script'),
        ('offline-reboot.sh', 'reboot',
         'reboot in an offline script'),
        ('capture-writes-nvram.sh', 'nvram boot-args="debug=0x108"',
         'nvram write in a capture script'),
        # ROUND 12: the verb in COMMAND POSITION must still be caught, in each
        # of the shapes a real script would use. Tightening the rule to
        # "invoked, not mentioned" must not become "never caught".
        ('offline-reboot-sudo.sh', 'sudo reboot',
         'sudo reboot in an offline script'),
        ('offline-reboot-abs.sh', '/sbin/reboot',
         'an absolute-path reboot'),
        ('offline-reboot-and.sh', 'echo done && reboot',
         'reboot after &&'),
        ('offline-shutdown.sh', 'sudo shutdown -r now',
         'shutdown in an offline script'),
        ('offline-bless.sh', 'sudo bless --mount /Volumes/X',
         'bless in an offline script'),
    ]
    for name, body, what in bad_cases:
        t = os.path.join(WORK, 'bad-' + name)
        shutil.copytree(base, t)
        plant(t, name, body)
        rc, out = run(t)
        caught = rc != 0 and name in out
        print('  %-26s %-42s %s'
              % (name, what, 'CAUGHT' if caught else 'NOT CAUGHT'))
        if not caught:
            print('      exit=%d output=%r' % (rc, out[:200]))
            ok = False

    # ---- legitimate forms that must be ACCEPTED ----
    good_cases = [
        ('readonly-nvram.sh', 'nvram boot-args 2>/dev/null || true',
         'reading boot-args'),
        ('readonly-kmutil.sh', 'kmutil showloaded --list-only', 'listing kexts'),
        ('readonly-dmesg.sh', 'sudo dmesg | tail -100', 'reading the kernel log'),
        ('comment-reboot.sh', '# remember to reboot afterwards\necho hi',
         'a comment that mentions rebooting'),
        # ROUND 12: a MENTION is not an INVOCATION.
        #
        # build-record.sh writes "written later, after a reboot" into the README
        # it generates, and the round-11 guard rejected it for the word. That is
        # the same category error as failing a capture script for reading
        # `nvram`: the verb was data, not an action. These three cases pin the
        # distinction so a future tightening cannot silently undo it.
        ('mention-reboot.sh',
         'echo "# the loaded identity is written after a reboot" > "$OUT/README"',
         'the word "reboot" inside output text'),
        ('mention-shutdown.sh',
         'printf "do not shutdown during a write\\n" >&2',
         'the word "shutdown" inside output text'),
        ('mention-bless.sh',
         'echo "no bless was run" >> "$LOG"',
         'the word "bless" inside output text'),
    ]
    for name, body, what in good_cases:
        t = os.path.join(WORK, 'good-' + name)
        shutil.copytree(base, t)
        plant(t, name, body)
        rc, out = run(t)
        accepted = rc == 0
        print('  %-26s %-42s %s'
              % (name, what, 'ACCEPTED' if accepted else 'REJECTED (wrong)'))
        if not accepted:
            print('      exit=%d output=%r' % (rc, out[:300]))
            ok = False

    # ---- a deploy script may still deploy ----
    t = os.path.join(WORK, 'good-deploy')
    shutil.copytree(base, t)
    plant(t, 'deploy-test.sh',
          'sudo kmutil load -p /Library/Extensions/X.kext\nnvram boot-args="-v"')
    rc, out = run(t)
    print('  %-26s %-42s %s'
          % ('deploy-test.sh', 'a deploy script deploys', 'ACCEPTED'
             if rc == 0 else 'REJECTED (wrong)'))
    if rc != 0:
        print('      exit=%d output=%r' % (rc, out[:200]))
        ok = False

    print()
    print('  RESULT: %s' % ('GUARD STILL WORKS' if ok else 'FAILURES'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
