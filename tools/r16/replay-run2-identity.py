#!/usr/bin/env python3
"""Bounded run2 replay ONLY in a new scratch directory, using verified archives.
Does not deploy/load/restart or edit original source trees / archive files.
Uses installed compiler/linker binaries but archived header/library inputs.
"""
import argparse,hashlib,importlib.util,json,os,re,shlex,subprocess,tarfile
from pathlib import Path,PurePosixPath
p=argparse.ArgumentParser();p.add_argument('--archive',required=True);p.add_argument('--scratch',required=True);p.add_argument('--layout-supplement');a=p.parse_args()
archive=Path(a.archive).resolve();scratch=Path(a.scratch).resolve()
assert archive.is_dir() and not scratch.exists()
for row in json.loads((archive/'ARCHIVES.json').read_text()):
 name=row['path'];assert Path(name).name==name
 assert (archive/name).stat().st_size==row['size'] and hashlib.sha256((archive/name).read_bytes()).hexdigest()==row['sha256'],name
# The original helper is captured as an external input. Import only its pure identity routines.
scratch.mkdir();total=0
for label in ('driver','probe','external'):
 dest=scratch/label;dest.mkdir();rows=json.loads((archive/(label+'-files.json')).read_text());expected={r['path']:r for r in rows};seen=set()
 with tarfile.open(archive/(label+'-source-binary.tar.gz'),'r:gz') as t:
  for m in t:
   q=PurePosixPath(m.name);assert m.isfile() and not q.is_absolute() and '..' not in q.parts and m.name in expected and m.name not in seen
   row=expected[m.name];assert m.size==row['size'];total+=m.size;assert total<=900_000_000
   data=t.extractfile(m).read();assert hashlib.sha256(data).hexdigest()==row['sha256'];seen.add(m.name)
   out=dest/m.name;out.parent.mkdir(parents=True,exist_ok=True)
   with out.open('xb') as f:f.write(data)
   out.chmod(m.mode & 0o777)
 assert seen==set(expected)
if a.layout_supplement:
 supplement=Path(a.layout_supplement);meta=json.loads((supplement/'manifest.json').read_text())
 assert hashlib.sha256((supplement/'layout-check-source.tar.gz').read_bytes()).hexdigest()==meta['archive_sha256']
 with tarfile.open(supplement/'layout-check-source.tar.gz') as t:
  assert t.getnames()==['tools/layout-check.cpp'];data=t.extractfile('tools/layout-check.cpp').read()
 assert len(data)==meta['source_size'] and hashlib.sha256(data).hexdigest()==meta['source_sha256']
 path=scratch/'probe/tools/layout-check.cpp';assert not path.exists()
 with path.open('xb') as f:f.write(data)
helpers=list((scratch/'external').rglob('archive-run1-identity.py'));assert len(helpers)==1
spec=importlib.util.spec_from_file_location('identity',helpers[0]);helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
record=json.loads((archive/'binary-identity.json').read_text());summary=json.loads((archive/'scope.json').read_text())
external=scratch/'external';resource_candidates=list(external.glob('Library/Developer/CommandLineTools/usr/lib/clang/*'))
resources=[q for q in resource_candidates if (q/'include').is_dir()];assert len(resources)<=1
extra=(' -resource-dir '+shlex.quote(str(resources[0]))) if resources else ''
# Patch scratch-only build scripts to prefer captured resource headers.
for label,name in [('driver','build-lucy.sh'),('probe','build-m1a.sh')]:
 path=scratch/label/'tools'/name;text=path.read_text()
 text=text.replace('CFLAGS="','CFLAGS="'+extra+' ',1)
 if label=='driver':text=text.replace('CFLAGS_C="','CFLAGS_C="'+extra+' ',1)
 else:
  candidates=list(external.glob('Library/Developer/CommandLineTools/SDKs/*/System/Library/Frameworks/Kernel.framework/Versions/A/Headers'))
  assert len(candidates)==1,candidates
  sdk=scratch/'sdk-overlay';sdk.mkdir()
  for source in (external/'Library/Developer/CommandLineTools/SDKs').glob('*.sdk'):
   for file in source.rglob('*'):
    if file.is_file():
     dest=sdk/file.relative_to(source);dest.parent.mkdir(parents=True,exist_ok=True)
     data=file.read_bytes()
     if dest.exists():assert dest.read_bytes()==data,str(dest)
     else:dest.write_bytes(data)
  assert (sdk/'usr/lib/libkmod.a').is_file(),sdk
  text=text.replace('SDK=$(xcrun --sdk macosx --show-sdk-path)','SDK='+shlex.quote(str(sdk)),1)
 path.write_text(text)
results={}
def build(label,normalized=False):
 root=scratch/label;script='build-lucy.sh' if label=='driver' else 'build-m1a.sh'
 output=(root/('build-lucy' if label=='driver' else 'build-m1a')).resolve()
 assert output.parent==root.resolve() and root.resolve().parent==scratch
 print('Verified scratch-only build cleanup target:',output,flush=True)
 log=scratch/(label+('-normalized' if normalized else '')+'-build.log')
 with log.open('xb') as f:
  proc=subprocess.run(['sh','tools/'+script],cwd=root,stdout=f,stderr=subprocess.STDOUT)
 assert proc.returncode==0,str(log)
 kext=root/('build-lucy/RTL812xLucy.kext' if label=='driver' else 'build-m1a/AMDMapperProbe.kext')
 ident=helper.bundle_identity(kext);want=record[label+'_built'];key=label+('_normalized' if normalized else '')
 result={'built':ident,'binary_sha256_matches_original':ident['binary_sha256']==want['binary_sha256'],'uuid_matches_original':ident['uuid']==want['uuid'],'bundle_manifest_matches_original':ident['bundle_manifest_sha256']==want['bundle_manifest_sha256']}
 if not result['binary_sha256_matches_original']:
  binary=next((kext/'Contents/MacOS').iterdir());raw=binary.read_bytes()
  result['scratch_compilation_path_present']=str(root).encode() in raw
  result['original_compilation_path_present']=summary[label+'_root'].encode() in raw
  # Record symbols and DWARF provenance without claiming a match.
  with (scratch/(key+'-symbols.txt')).open('xb') as f:subprocess.run(['nm',str(binary)],stdout=f,stderr=subprocess.STDOUT,check=True)
  with (scratch/(key+'-debug-info.txt')).open('xb') as f:subprocess.run(['xcrun','dwarfdump','--debug-info',str(binary)],stdout=f,stderr=subprocess.STDOUT,check=True)
 results[key]=result
 with (scratch/'replay-results.json').open('w') as f:json.dump(results,f,indent=2)
 print(key,json.dumps({k:v for k,v in result.items() if k!='built'}),flush=True)
build('driver');build('probe')
if not results['probe']['binary_sha256_matches_original']:
 # A second bounded replay preserves original debug paths; no original files changed.
 path=scratch/'probe/tools/build-m1a.sh';text=path.read_text()
 options=' -fdebug-compilation-dir='+shlex.quote(summary['probe_root'])+' -fdebug-prefix-map='+shlex.quote(str(scratch/'probe')+'='+summary['probe_root'])+' -fdebug-prefix-map='+shlex.quote(str(external)+'=')+' -fdebug-prefix-map='+shlex.quote(str(scratch/'sdk-overlay')+'='+summary['sys_sdk'])
 text=text.replace('CFLAGS="','CFLAGS="'+options+' ',1);path.write_text(text)
 build('probe',True)
print('Replay completed without deployment:',scratch,flush=True)
