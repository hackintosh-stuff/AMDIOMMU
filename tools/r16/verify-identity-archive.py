#!/usr/bin/env python3
"""Verify downloaded source/binary identity archives without extraction/replay."""
import argparse,hashlib,json,tarfile
from pathlib import Path,PurePosixPath
p=argparse.ArgumentParser();p.add_argument('directory');a=p.parse_args();root=Path(a.directory)
def digest(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
for row in json.loads((root/'ARCHIVES.json').read_text()):
 name=row['path'];assert Path(name).name==name
 assert (root/name).stat().st_size==row['size'] and digest(root/name)==row['sha256'],name
summary=json.loads((root/'scope.json').read_text());total=0;counts={};archives={}
for label in ('driver','probe','external'):
 rows=json.loads((root/(label+'-files.json')).read_text());expected={r['path']:r for r in rows}
 assert len(rows)==len(expected);seen=set();size=0
 with tarfile.open(root/(label+'-source-binary.tar.gz'),'r:gz') as t:
  for m in t:
   assert m.isfile() and m.name in expected and m.name not in seen,m.name
   path=PurePosixPath(m.name);assert not path.is_absolute() and '..' not in path.parts
   row=expected[m.name];assert m.size==row['size'];h=hashlib.sha256()
   with t.extractfile(m) as f:
    for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
   assert h.hexdigest()==row['sha256'],m.name
   size+=m.size;seen.add(m.name)
 assert seen==set(expected)
 assert len(seen)==summary['file_counts'][label] and size==summary['uncompressed_file_bytes'][label]
 total+=size;counts[label]=len(seen);archives[label]=digest(root/(label+'-source-binary.tar.gz'))
assert total==summary['total_input_bytes'] and total<=900_000_000
identity=json.loads((root/'binary-identity.json').read_text())
for label in ('driver','probe'):
 comparison=identity[label+'_comparison']
 for key in ('built_uuid_matches_capture','built_sha256_matches_load_source','built_bundle_matches_load_source'):
  assert comparison[key] is True,comparison
 assert identity[label+'_built']['uuid']==comparison['captured_loaded_uuid']
 rows={r['path']:r for r in json.loads((root/(label+'-files.json')).read_text())}
 prefix='build-lucy/RTL812xLucy.kext/' if label=='driver' else 'build-m1a/AMDMapperProbe.kext/'
 for row in identity[label+'_built']['files']:
  archived=rows[prefix+row['path']]
  assert archived['size']==row['size'] and archived['sha256']==row['sha256']
supp=root/'replay/r16-run2-layout-supplement'
if supp.exists():
 meta=json.loads((supp/'manifest.json').read_text())
 assert digest(supp/'layout-check-source.tar.gz')==meta['archive_sha256']
 with tarfile.open(supp/'layout-check-source.tar.gz') as t:
  assert t.getnames()==['tools/layout-check.cpp']
  data=t.extractfile('tools/layout-check.cpp').read()
  assert len(data)==meta['source_size'] and hashlib.sha256(data).hexdigest()==meta['source_sha256']
print(json.dumps({'status':'PASS','layout_supplement_verified':supp.exists(),'verified_file_counts':counts,'total_input_bytes':total,'archives_sha256':archives,'identity':{k:v for k,v in identity.items() if k.endswith('comparison')}},indent=2))
