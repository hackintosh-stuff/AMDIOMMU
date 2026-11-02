#!/usr/bin/env python3
"""Bounded continuation after the scratch probe linked/signed but lacked layout-check.cpp.
Never changes original source/bundles/archives. Creates a tiny separate supplement.
"""
import hashlib,importlib.util,json,shlex,struct,subprocess,tarfile
from pathlib import Path
archive=Path('/Users/ling/r16-run2-source-identity-v2');scratch=Path('/Users/ling/r16-run2-replay');probe=scratch/'probe'
supp=Path('/Users/ling/r16-run2-layout-supplement');assert not supp.exists();supp.mkdir()
source=Path('/Users/ling/r12work/tools/layout-check.cpp');assert source.stat().st_size<65536
with tarfile.open(str(supp/'layout-check-source.tar.gz'),'x:gz') as t:t.add(str(source),arcname='tools/layout-check.cpp',recursive=False)
meta={'source_original_path':str(source),'source_size':source.stat().st_size,'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'archive_sha256':hashlib.sha256((supp/'layout-check-source.tar.gz').read_bytes()).hexdigest(),'scope':'Postbuild user-space layout-check source only; uses installed matching CLT standard C++ headers/runtime. Does not participate in probe kext binary.'}
(supp/'manifest.json').write_text(json.dumps(meta,indent=2)+'\n')
with tarfile.open(supp/'layout-check-source.tar.gz') as t:
 data=t.extractfile('tools/layout-check.cpp').read();assert hashlib.sha256(data).hexdigest()==meta['source_sha256']
 out=probe/'tools/layout-check.cpp';assert not out.exists()
 with out.open('xb') as f:f.write(data)
helperfile=next((scratch/'external').rglob('archive-run1-identity.py'))
spec=importlib.util.spec_from_file_location('identity',helperfile);helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
record=json.loads((archive/'binary-identity.json').read_text());scope=json.loads((archive/'scope.json').read_text());results=json.loads((scratch/'replay-results.json').read_text())
original=scratch/'original-probe.bin'
with tarfile.open(archive/'probe-source-binary.tar.gz') as t:
 with original.open('xb') as f:f.write(t.extractfile('build-m1a/AMDMapperProbe.kext/Contents/MacOS/AMDMapperProbe').read())
def text_sections(path):
 b=path.read_bytes();n=struct.unpack_from('<I',b,16)[0];off=32;result={}
 for _ in range(n):
  cmd,size=struct.unpack_from('<II',b,off)
  if cmd==0x19:
   count=struct.unpack_from('<I',b,off+64)[0];pos=off+72
   for _ in range(count):
    name=b[pos:pos+16].split(b'\0')[0].decode();seg=b[pos+16:pos+32].split(b'\0')[0].decode();sz=struct.unpack_from('<Q',b,pos+40)[0];start=struct.unpack_from('<I',b,pos+48)[0]
    if name=='__text':result[seg+','+name]=hashlib.sha256(b[start:start+sz]).hexdigest()
    pos+=80
  off+=size
 return result
binary=probe/'build-m1a/AMDMapperProbe.kext/Contents/MacOS/AMDMapperProbe'
def capture(label):
 ident=helper.bundle_identity(binary.parents[2]);want=record['probe_built'];data=binary.read_bytes()
 names=lambda path:subprocess.check_output(['nm','-gj',str(path)],text=True).splitlines()
 item={'built':ident,'binary_sha256_matches_original':ident['binary_sha256']==want['binary_sha256'],'uuid_matches_original':ident['uuid']==want['uuid'],'bundle_manifest_matches_original':ident['bundle_manifest_sha256']==want['bundle_manifest_sha256'],'text_sections_match_original':text_sections(binary)==text_sections(original),'nm_external_symbol_names_match_original':sorted(names(binary))==sorted(names(original)),'scratch_compilation_path_present':str(probe).encode() in data,'original_compilation_path_present':scope['probe_root'].encode() in data,'postbuild_layout_source_supplement':meta}
 if not item['binary_sha256_matches_original']:
  with (scratch/(label+'-debug-info.txt')).open('xb') as f:subprocess.run(['xcrun','dwarfdump','--debug-info',str(binary)],stdout=f,stderr=subprocess.STDOUT,check=True)
 results[label]=item;(scratch/'replay-results.json').write_text(json.dumps(results,indent=2)+'\n')
 print(label,json.dumps({k:v for k,v in item.items() if k not in ('built','postbuild_layout_source_supplement')}),flush=True)
capture('probe')
with (scratch/'probe-layout-check-supplement.log').open('xb') as f:
 subprocess.run(['xcrun','clang++','-std=c++17','-O0','-o',str(scratch/'probe-layout-check'),'tools/layout-check.cpp'],cwd=probe,stdout=f,stderr=subprocess.STDOUT,check=True)
 subprocess.run([str(scratch/'probe-layout-check')],stdout=f,stderr=subprocess.STDOUT,check=True)
if not results['probe']['binary_sha256_matches_original']:
 script=probe/'tools/build-m1a.sh';text=script.read_text();external=scratch/'external'
 options=' -fdebug-compilation-dir='+scope['probe_root']+' -fdebug-prefix-map='+str(probe)+'='+scope['probe_root']+' -fdebug-prefix-map='+str(external)+'='+' -fdebug-prefix-map='+str(scratch/'sdk-overlay')+'='+scope['sys_sdk']
 script.write_text(text.replace('CFLAGS="','CFLAGS="'+options+' ',1))
 target=(probe/'build-m1a').resolve();assert target.parent==probe.resolve() and probe.resolve().parent==scratch
 print('Verified scratch-only cleanup target:',target,flush=True)
 with (scratch/'probe-normalized-build.log').open('xb') as f:subprocess.run(['sh','tools/build-m1a.sh'],cwd=probe,stdout=f,stderr=subprocess.STDOUT,check=True)
 capture('probe_normalized')
print('Bounded probe continuation done; installed bundles and original archives untouched.',flush=True)
