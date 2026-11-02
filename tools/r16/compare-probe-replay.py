"""Read-only Mach-O section/STAB provenance comparison; never rebuilds."""
import hashlib,json,struct
from pathlib import Path
root=Path('/Users/ling/r16-run2-replay')
paths={'original':root/'original-probe.bin','normalized':root/'probe/build-m1a/AMDMapperProbe.kext/Contents/MacOS/AMDMapperProbe'}
def parse(path):
 b=path.read_bytes();n=struct.unpack_from('<I',b,16)[0];off=32;sections={};stab=[];sym=None
 for _ in range(n):
  cmd,size=struct.unpack_from('<II',b,off)
  if cmd==0x2:sym=struct.unpack_from('<IIII',b,off+8)
  if cmd==0x19:
   count=struct.unpack_from('<I',b,off+64)[0];pos=off+72
   for _ in range(count):
    name=b[pos:pos+16].split(b'\0')[0].decode();seg=b[pos+16:pos+32].split(b'\0')[0].decode();sz=struct.unpack_from('<Q',b,pos+40)[0];start=struct.unpack_from('<I',b,pos+48)[0];flags=struct.unpack_from('<I',b,pos+64)[0]
    if (flags & 0xff) not in (1,12,18):sections[seg+','+name]={'size':sz,'sha256':hashlib.sha256(b[start:start+sz]).hexdigest()}
    pos+=80
  off+=size
 if sym:
  so,ns,st,ss=sym
  for i in range(ns):
   ix,ty,se,de,value=struct.unpack_from('<IBBHQ',b,so+i*16)
   if ty & 0xe0:
    name=b[st+ix:b.find(b'\0',st+ix)].decode(errors='replace') if ix else ''
    if ty in (0x64,0x66) and name:stab.append({'type':hex(ty),'name':name,'value':value})
 return {'sections':sections,'source_and_object_STAB':stab}
x={k:parse(v) for k,v in paths.items()};names=set(x['original']['sections'])|set(x['normalized']['sections']);matches={n:x['original']['sections'].get(n)==x['normalized']['sections'].get(n) for n in sorted(names)}
result={'all_file_backed_sections_match':all(matches.values()),'sections_match':matches,'provenance':x,'conclusion':'Compare proves section equality/differences and records N_SO/N_OSO paths/time values; it does not assert byte identity or that no other metadata differs.'}
(root/'probe-macho-comparison.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'all_file_backed_sections_match':result['all_file_backed_sections_match'],'sections_match':matches,'original_STAB_examples':x['original']['source_and_object_STAB'][:4],'normalized_STAB_examples':x['normalized']['source_and_object_STAB'][:4]},indent=2))
