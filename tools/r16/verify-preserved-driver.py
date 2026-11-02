"""Verify the bounded run1 source-identity archive without extracting/replaying."""
import argparse,hashlib,json,tarfile
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('archive');a=p.parse_args()
path=Path(a.archive);meta=json.loads(Path(str(path)+'.manifest.json').read_text())
assert hashlib.sha256(path.read_bytes()).hexdigest()==meta['archive_sha256']
expected={r['path']:r for r in meta['files']};seen=set();total=0;binary=None
with tarfile.open(str(path),'r:gz') as t:
 for m in t:
  assert m.isfile() and m.name in expected and m.name not in seen,m.name
  r=expected[m.name];assert m.size==r['size']
  assert total+m.size<=400_000_000
  with t.extractfile(m) as f:data=f.read()
  digest=hashlib.sha256(data).hexdigest();assert digest==r['sha256'],m.name
  if m.name=='build-lucy/RTL812xLucy.kext/Contents/MacOS/RTL812xLucy':binary=digest
  total+=m.size;seen.add(m.name)
assert seen==set(expected) and total==meta['total_bytes']
assert binary=='f8e82e073efdb02b564a09f3ed38a237ba2df6be81c95a2df019abc206d70f0d'
print(json.dumps({'status':'PASS','files':len(seen),'input_bytes':total,'archive_bytes':path.stat().st_size,'archive_sha256':meta['archive_sha256'],'binary_sha256':binary},indent=2))
