import hashlib,json,plistlib,struct,uuid
from pathlib import Path
root=Path('/Users/ling/r16-driver-staging-agent')
kext=root/'build-lucy/RTL812xLucy.kext'
p=kext/'Contents/MacOS/RTL812xLucy'
b=p.read_bytes();n=struct.unpack_from('<I',b,16)[0];off=32;ident=None
for _ in range(n):
 cmd,size=struct.unpack_from('<II',b,off)
 if cmd==0x1b:ident=str(uuid.UUID(bytes=b[off+8:off+24])).upper()
 off+=size
plist=plistlib.loads((kext/'Contents/Info.plist').read_bytes())
rows=[{'path':str(q.relative_to(kext)),'size':q.stat().st_size,'sha256':hashlib.sha256(q.read_bytes()).hexdigest()} for q in sorted(kext.rglob('*')) if q.is_file()]
old=Path('/Users/ling/r16-driver-agent/build-lucy/RTL812xLucy.kext/Contents/MacOS/RTL812xLucy').read_bytes()
result={'binary_sha256':hashlib.sha256(b).hexdigest(),'uuid':ident,'version':plist['CFBundleVersion'],'short_version':plist['CFBundleShortVersionString'],'kmod_version_present':b'1.1.201\0' in b,'staging_mode_present':b'page-aligned-real-tx-staging-v1' in b,'bundle_files':rows,'bundle_manifest_sha256':hashlib.sha256(''.join(r['sha256']+'  '+r['path']+'\n' for r in rows).encode()).hexdigest(),'run1_old_binary_sha256':hashlib.sha256(old).hexdigest(),'run1_preservation_archive_sha256':hashlib.sha256(Path('/Users/ling/r16-driver-run1-preserved.tar.gz').read_bytes()).hexdigest()}
with (root/'build-identity.json').open('x') as f:json.dump(result,f,indent=2);f.write('\n')
print(json.dumps(result,indent=2))
