#!/usr/bin/env python3
"""Read-only build input capture for run1. Writes exclusively a new output path.
No deployment, loading, or edits to either original build tree.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import struct
import subprocess
import tarfile
import uuid

DRIVER=Path('/Users/ling/r16-driver-agent')
PROBE=Path('/Users/ling/r12work')

def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def run(cmd,cwd=None):
 p=subprocess.run(cmd,cwd=cwd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
 if p.returncode:raise RuntimeError('%r returned %d\n%s'%(cmd,p.returncode,p.stdout))
 return p.stdout

def tree(p):
 if p.is_file():return [p]
 out=[]
 for d,dirs,files in os.walk(p,followlinks=True):
  dirs[:]=[n for n in dirs if n not in ('.git','__pycache__','.DS_Store')]
  for n in files:
   q=Path(d)/n
   if q.is_file() and n!='.DS_Store':out.append(q)
 return out

def flags(text,name,variables):
 m=re.search(r'^'+name+r'="(.*?)"',text,re.M|re.S)
 if not m:raise RuntimeError('missing flags '+name)
 s=m.group(1).replace('\\\n',' ')
 for k,v in sorted(variables.items(),key=lambda kv:-len(kv[0])):s=s.replace('$'+k,v)
 if '$' in s:raise RuntimeError('unexpanded '+s)
 return shlex.split(s)

def deps(root,script,driver=False):
 text=(root/script).read_text(); commands=[]; raw=[]; inputs=set()
 if driver:
  src=next(root.glob('RTL812xLucy-*'));rel=src.name
  variables={'SDK':rel+'/MacKernelSDK','SRC':rel,'DRV':rel+'/RTL812xLucy'}
  cf=flags(text,'CFLAGS',variables);cc=flags(text,'CFLAGS_C',variables)
  sources=sorted((src/'RTL812xLucy').glob('*.cpp'))+sorted((src/'RTL812xLucy').glob('*.c'))+[root/'tools/build/lucy-kmod-info.cpp']
 else:
  sdk=run(['xcrun','--sdk','macosx','--show-sdk-path']).strip()
  ver=run(['xcrun','--sdk','macosx','--show-sdk-version']).strip()
  cf=flags(text,'CFLAGS',{'SDK':sdk,'SDKVER':ver,'HEADERS':sdk+'/System/Library/Frameworks/Kernel.framework/Versions/A/Headers'})
  srclist=re.search(r'^SRCS="(.*?)"',text,re.M|re.S).group(1).replace('\\\n',' ')
  sources=[root/s for s in shlex.split(srclist)]
 for p in sources:
  s=str(p.relative_to(root));c=p.suffix=='.c'
  cmd=['xcrun','clang' if c else 'clang++']+(['-x','c'] if c else [])+(cc if c else cf)+['-M',s]
  proc=subprocess.run(cmd,cwd=root,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
  if proc.returncode:raise RuntimeError('%r returned %d\n%s\n%s'%(cmd,proc.returncode,proc.stdout,proc.stderr))
  result=proc.stdout;commands.append({'cwd':str(root),'argv':cmd})
  raw.append({'source':s,'make_dependencies':result,'diagnostics':proc.stderr})
  deptext=result.replace('\\\n',' ').split(':',1)[1]
  for name in shlex.split(deptext):
   q=Path(name)
   if not q.is_absolute():q=root/q
   if not q.is_file():raise RuntimeError('missing dependency '+str(q))
   inputs.add(q.resolve())
 return commands,raw,inputs

def macho_uuid(p):
 b=p.read_bytes();magic,ncmds=struct.unpack_from('<I12xI',b)
 if magic!=0xfeedfacf:raise ValueError('not thin Mach-O64: '+str(p))
 off=32
 for _ in range(ncmds):
  cmd,size=struct.unpack_from('<II',b,off)
  if cmd==0x1b:return str(uuid.UUID(bytes=b[off+8:off+24])).upper()
  off+=size
 raise ValueError('missing UUID')

def bundle_identity(p):
 files=tree(p);rows=[{'path':str(f.relative_to(p)),'size':f.stat().st_size,'sha256':sha(f)} for f in sorted(files)]
 canonical=''.join(x['sha256']+'  '+x['path']+'\n' for x in rows).encode()
 bins=list((p/'Contents/MacOS').iterdir());assert len(bins)==1
 return {'path':str(p),'binary_sha256':sha(bins[0]),'uuid':macho_uuid(bins[0]),'bundle_manifest_sha256':hashlib.sha256(canonical).hexdigest(),'files':rows}

def main():
 global DRIVER,PROBE
 p=argparse.ArgumentParser();p.add_argument('--out',required=True);p.add_argument('--plan',action='store_true')
 p.add_argument('--driver-root',default=str(DRIVER));p.add_argument('--probe-root',default=str(PROBE))
 p.add_argument('--load-root',default='/Users/ling/r16load')
 p.add_argument('--extra-file',action='append',default=[])
 p.add_argument('--driver-log',default='build-driver.log');p.add_argument('--run-label',default='Run1')
 p.add_argument('--driver-uuid',default='E68B67E7-D7DC-33D0-A2FD-C0B261697F97')
 p.add_argument('--probe-uuid',default='5C4D5A32-3934-3BA6-850E-2D7E1659AC60')
 a=p.parse_args();DRIVER=Path(a.driver_root).resolve();PROBE=Path(a.probe_root).resolve();load=Path(a.load_root).resolve()
 out=Path(a.out)
 if out.exists():raise RuntimeError('refuse overwrite '+str(out))
 ds=next(DRIVER.glob('RTL812xLucy-*'))
 paths={'driver':set(),'probe':set(),'external':{Path(__file__).resolve()}}
 for rel in [str(ds.relative_to(DRIVER))+'/RTL812xLucy',str(ds.relative_to(DRIVER))+'/KernelSPI',str(ds.relative_to(DRIVER))+'/MacKernelSDK','tools/build/patch-lucy-obs.py','tools/build/lucy.sh','tools/build/lucy-kmod-info.cpp','tools/lucy-obs','tools/r16','build-lucy/RTL812xLucy.kext',a.driver_log,'build-identity.json','test-driver-staging.log']:
  paths['driver'].update(tree(DRIVER/rel))
 for rel in ['kext','tools/build/probe.sh','tools/dev/layout-check.cpp','tools/lucy-obs','tools/r16','build-m1a/AMDMapperProbe.kext']:
  paths['probe'].update(tree(PROBE/rel))
 # Existing probe build logs, if present (not invented by this post-run capture).
 logs=[q for q in PROBE.glob('*') if q.is_file() and q.suffix in ('.log','.txt') and ('build' in q.name or 'r16' in q.name)]
 paths['probe'].update(logs)
 dc,dr,di=deps(DRIVER,Path('tools/build/lucy.sh'),True)
 pc,pr,pi=deps(PROBE,Path('tools/build/probe.sh'))
 for q in di|pi:
  if str(q).startswith(str(DRIVER)+'/'):paths['driver'].add(q)
  elif str(q).startswith(str(PROBE)+'/'):paths['probe'].add(q)
  else:paths['external'].add(q)
 for q in [Path('/tmp/r16-probe-build-final.log'),Path('/tmp/r16-deploy.log'),Path('/tmp/r16-disarm-next.log'),Path('/tmp/r16-tx-test')]:
  if q.is_file():paths['external'].add(q)
 for q in tree(load):
  if '.kext/' not in str(q) and q.suffix in ('.py','.sh','.plist','.txt'):
   paths['external'].add(q)
 sdk=Path(run(['xcrun','--sdk','macosx','--show-sdk-path']).strip())
 for q in [sdk/'SDKSettings.plist',sdk/'usr/lib/libkmod.a']:
  if q.is_file():paths['external'].add(q)
 for name in a.extra_file:
  q=Path(name).resolve()
  if not q.is_file():raise RuntimeError('missing explicitly requested extra '+str(q))
  paths['external'].add(q)
 sizes={name:sum(q.stat().st_size for q in values) for name,values in paths.items()}
 total=sum(sizes.values())
 summary={'run_label':a.run_label,'load_root':str(load),'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'uncompressed_file_bytes':sizes,'total_input_bytes':total,'file_counts':{k:len(v) for k,v in paths.items()},'driver_root':str(DRIVER),'probe_root':str(PROBE),'sys_sdk':str(sdk)}
 print(json.dumps(summary,indent=2))
 if total>=900_000_000:raise RuntimeError('backup preflight over conservative <1GB limit')
 if a.plan:return
 out.mkdir(parents=True,exist_ok=False)
 (out/'scope.json').write_text(json.dumps(summary,indent=2)+'\n')
 toolchain={}
 for key,cmd in [('clang',['xcrun','clang++','--version']),('ld',['xcrun','ld','-v']),('os',['sw_vers']),('kernel',['uname','-a']),('xcode_select',['xcode-select','-p'])]:toolchain[key]=run(cmd)
 for tool in ['clang++','ld']:
  q=Path(run(['xcrun','--find',tool]).strip());toolchain[tool+'_path']=str(q);toolchain[tool+'_sha256']=sha(q)
 (out/'toolchain.json').write_text(json.dumps(toolchain,indent=2)+'\n')
 (out/'compiler-dependencies.json').write_text(json.dumps({'driver_commands':dc,'probe_commands':pc,'driver_raw':dr,'probe_raw':pr},indent=2)+'\n')
 identities={
 'driver_built':bundle_identity(DRIVER/'build-lucy/RTL812xLucy.kext'),
 'probe_built':bundle_identity(PROBE/'build-m1a/AMDMapperProbe.kext'),
 'driver_load_source':bundle_identity(load/'RTL812xLucy.kext'),
 'probe_load_source':bundle_identity(load/'AMDMapperProbe.kext')}
 for name,expected in [('driver',str(uuid.UUID(a.driver_uuid)).upper()),('probe',str(uuid.UUID(a.probe_uuid)).upper())]:
  built=identities[name+'_built'];loaded=identities[name+'_load_source']
  identities[name+'_comparison']={'captured_loaded_uuid':expected,'built_uuid_matches_capture':built['uuid']==expected,'built_sha256_matches_load_source':built['binary_sha256']==loaded['binary_sha256'],'built_bundle_matches_load_source':built['bundle_manifest_sha256']==loaded['bundle_manifest_sha256']}
 (out/'binary-identity.json').write_text(json.dumps(identities,indent=2)+'\n')
 roots={'driver':DRIVER,'probe':PROBE,'external':Path('/')}
 manifest=[]
 for name,files in paths.items():
  rows=[]
  with tarfile.open(str(out/(name+'-source-binary.tar.gz')),'x:gz',dereference=True) as tf:
   for q in sorted(files):
    rel=str(q.relative_to(roots[name]));row={'path':rel,'size':q.stat().st_size,'sha256':sha(q)};rows.append(row)
    tf.add(str(q),arcname=rel,recursive=False)
  (out/(name+'-files.json')).write_text(json.dumps(rows,indent=2)+'\n')
  manifest.append({'path':name+'-source-binary.tar.gz','size':(out/(name+'-source-binary.tar.gz')).stat().st_size,'sha256':sha(out/(name+'-source-binary.tar.gz'))})
 (out/'ARCHIVES.json').write_text(json.dumps(manifest,indent=2)+'\n')
 # Immutable snapshots can be replayed elsewhere; no original build tree is touched.
 (out/'README.txt').write_text(a.run_label+' post-capture build identity. No installed system files modified.\n'
  'driver archive: generated driver, complete linux/ and MacKernelSDK headers/libraries, KernelSPI, generator/templates/shared ABI/kmod-info/build script/log and final signed bundle.\n'
  'probe archive: complete kext/ plus actual build script/shared headers and final bundle/build logs found.\n'
  'external archive: compiler -M dependency closure outside project roots plus SDKSettings/libkmod; original absolute paths recorded as root-relative members.\n'
  'Compiler executable hashes and versions identify provenance; compiler executables are NOT backed up.\n'
  'To rebuild driver: extract driver archive into a new writable directory, then sh tools/build/lucy.sh (requires matching CLT toolchain). It replaces ONLY the new directory build-lucy/.\n'
  'To rebuild probe: extract probe archive into new directory, sh tools/build/probe.sh with matching CLT/macOS SDK. Probe uses -g; original compilation root /Users/ling/r12work is encoded in debug information. Different replay root may change UUID/hash; preserve/rebase debug compilation directory if checking exact bytes.\n'
  'Binary UUID equality with captured loaded UUID links build to running image identity; binary SHA equality links build to captured load-source files, not an independently hashed running kernel image.\n')
 print('ARCHIVE DONE',out)
 print(json.dumps({k:v for k,v in identities.items() if k.endswith('comparison')},indent=2))
if __name__=='__main__':main()
