import hashlib,json,os,tarfile
from pathlib import Path
root=Path('/Users/ling/r16-driver-agent')
out=Path('/Users/ling/r16-driver-run1-preserved.tar.gz')
assert not out.exists()
files=[]
for base,dirs,names in os.walk(root):
 dirs[:]=[d for d in dirs if d not in ('__pycache__','.git')]
 for n in names:
  p=Path(base)/n
  if p.is_file() and p.suffix!='.o':files.append(p)
size=sum(p.stat().st_size for p in files)
assert size<400_000_000,size
print('run1 preservation inputs',len(files),size,'bytes')
rows=[]
with tarfile.open(str(out),'x:gz',dereference=True) as t:
 for p in sorted(files):
  rows.append({'path':str(p.relative_to(root)),'size':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})
  t.add(str(p),arcname=str(p.relative_to(root)),recursive=False)
Path(str(out)+'.manifest.json').write_text(json.dumps({'total_bytes':size,'archive_sha256':hashlib.sha256(out.read_bytes()).hexdigest(),'files':rows},indent=2)+'\n')
print(out,out.stat().st_size)
