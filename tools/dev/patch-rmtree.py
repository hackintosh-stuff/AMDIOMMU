"""Add a read-only-tolerant rmtree to the round-12/13 verifiers.

WHY THIS IS A SEPARATE PATCH
----------------------------
These scripts run on Windows (where the workspace lives) as well as on the Mac.
A tree copied from `docs/evidence/` can carry attributes that make
`shutil.rmtree` fail with WinError 5, which aborted the verifier at the point
where it was rebuilding its scratch directory -- a cleanup failure reported as
a test failure. The same defect hit test-analyzer12.py.

Only the call sites that remove the scratch tree are changed; nothing about
what the verifier asserts is touched.
"""
import re
import sys

HELPER = '''
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

'''

for path in sys.argv[1:]:
    s = open(path, encoding='utf-8').read()
    if 'def rmtree_force(' in s:
        print('%s: already patched' % path)
        continue
    if 'shutil.rmtree(WORK)' not in s:
        print('%s: no shutil.rmtree(WORK) call' % path)
        continue
    # insert the helper right after the last import line
    m = list(re.finditer(r'^(?:import|from) .*$', s, re.M))
    at = m[-1].end()
    s = s[:at] + '\n' + HELPER + s[at:]
    s = s.replace('shutil.rmtree(WORK)', 'rmtree_force(WORK)')
    open(path, 'w', encoding='utf-8', newline='\n').write(s)
    print('%s: patched' % path)
