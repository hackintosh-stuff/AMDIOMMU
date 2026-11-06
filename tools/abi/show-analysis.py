import json
import sys

r = json.load(open(sys.argv[1]))
print('ok', r['ok'], len(r['checks']), 'checks')
for c in r['checks']:
    if c['state'] != 'ok':
        print('FAIL', c['id'], c.get('detail'))
for c in r['checks']:
    if c['id'].startswith(('runtime', 'tx-ring', 'real-multi')):
        print(c['id'], json.dumps(c.get('detail'), indent=1))
print('ring', r['details']['ring'])
