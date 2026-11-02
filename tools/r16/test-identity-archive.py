"""Host-independent fixture test of archive mechanics; not an actual build replay."""
import contextlib,hashlib,importlib.util,io,json,struct,sys,tarfile,tempfile,uuid
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('capture',Path(__file__).with_name('archive-run1-identity.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
with tempfile.TemporaryDirectory() as td:
 root=Path(td);driver=root/'driver';probe=root/'probe';load=root/'load';sdk=root/'sdk';compiler=root/'clang'
 compiler.write_bytes(b'fixture-compiler-not-executed')
 did='CFB1FD8C-BB30-3CE3-A9EA-8FD0508206C1';pid='5C4D5A32-3934-3BA6-850E-2D7E1659AC60'
 def bundle(path,ident,name):
  binary=path/'Contents/MacOS'/name;binary.parent.mkdir(parents=True)
  binary.write_bytes(struct.pack('<8I',0xfeedfacf,0x1000007,3,11,1,24,0,0)+struct.pack('<II',0x1b,24)+uuid.UUID(ident).bytes)
  (path/'Contents/Info.plist').write_text('fixture plist')
 for base in (driver,probe):
  (base/'tools').mkdir(parents=True);(base/'tools/build-lucy.sh').write_text('fixture only')
 (driver/'RTL812xLucy-fixture/RTL812xLucy').mkdir(parents=True)
 (driver/'RTL812xLucy-fixture/RTL812xLucy/A.cpp').write_text('fixture source')
 (driver/'build-driver-staging.log').write_text('fixture build log')
 (probe/'kext').mkdir();(probe/'kext/A.cpp').write_text('fixture source')
 (sdk/'usr/lib').mkdir(parents=True);(sdk/'usr/lib/libkmod.a').write_bytes(b'fixture library')
 (sdk/'SDKSettings.json').write_text('{}')
 bundle(driver/'build-lucy/RTL812xLucy.kext',did,'RTL812xLucy')
 bundle(probe/'build-m1a/AMDMapperProbe.kext',pid,'AMDMapperProbe')
 bundle(load/'RTL812xLucy.kext',did,'RTL812xLucy')
 bundle(load/'AMDMapperProbe.kext',pid,'AMDMapperProbe')
 used=sdk/'used-header.h';used.write_text('fixture used header')
 def fake_run(cmd,cwd=None):
  if cmd[:2]==['xcrun','--find']:return str(compiler)+'\n'
  if '--show-sdk-path' in cmd:return str(sdk)+'\n'
  return 'fixture toolchain metadata\n'
 calls=[]
 def fake_deps(base,script,driver=False):
  calls.append((str(base),script,driver));return [{'fixture':True}],[],{used}
 out=root/'capture'
 args=['capture','--out',str(out),'--driver-root',str(driver),'--probe-root',str(probe),'--load-root',str(load),'--driver-log','build-driver-staging.log','--driver-uuid',did,'--probe-uuid',pid,'--run-label','fixture-run2']
 with patch.object(m,'run',fake_run),patch.object(m,'deps',fake_deps),contextlib.redirect_stdout(io.StringIO()):
  with patch.object(sys,'argv',args+['--plan']):m.main()
  assert not out.exists(), 'plan wrote output'
  with patch.object(sys,'argv',args):m.main()
  identity=json.loads((out/'binary-identity.json').read_text())
  for label in ('driver','probe'):assert all(identity[label+'_comparison'].values())
  for label in ('driver','probe','external'):
   rows=json.loads((out/(label+'-files.json')).read_text());expected={r['path']:r for r in rows}
   with tarfile.open(out/(label+'-source-binary.tar.gz')) as t:
    assert set(t.getnames())==set(expected)
    for member in t:
     assert member.isfile() and '..' not in Path(member.name).parts
     data=t.extractfile(member).read();row=expected[member.name]
     assert len(data)==row['size'] and hashlib.sha256(data).hexdigest()==row['sha256']
  try:
   with patch.object(sys,'argv',args):m.main()
  except RuntimeError as e:assert 'overwrite' in str(e)
  else:raise AssertionError('existing output accepted')
 assert len(calls)==4
print('PASS: fixture plan no-write, source/bundle/dependency archive, file hashes, UUID/load-source matching, existing-output refusal; compiler/deps mocked, no replay')
