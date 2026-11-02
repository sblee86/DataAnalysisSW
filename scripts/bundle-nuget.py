#!/usr/bin/env python3
"""Copy original restored .nupkg archives into the repository's offline feed."""
from pathlib import Path
import argparse,base64,hashlib,json,shutil
parser=argparse.ArgumentParser();parser.add_argument('--cache',type=Path,required=True);parser.add_argument('--prune-obsolete',action='store_true');args=parser.parse_args()
root=Path(__file__).resolve().parents[1]; assets=json.loads((root/'src/LanScope/obj/project.assets.json').read_text())
needed={(v['path'].split('/')[0],v['path'].split('/')[1]) for v in assets['libraries'].values() if v.get('type')=='package'}
for framework in assets['project']['frameworks'].values():
 for item in framework.get('downloadDependencies',[]):needed.add((item['name'].lower(),item['version'].strip('[]').split(',')[0]))
feed=root/'nuget-offline';feed.mkdir(exist_ok=True);manifest=[]
for name,version in sorted(needed):
 p=args.cache/name/version/f'{name}.{version}.nupkg';raw=p.read_bytes()
 if base64.b64encode(hashlib.sha512(raw).digest()).decode()!=p.with_name(p.name+'.sha512').read_text().strip(): raise SystemExit(f'Package cache hash mismatch: {p.name}')
 shutil.copy2(p,feed/p.name);manifest.append(dict(file=p.name,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))
# Remove only obsolete packages recorded in the previous generated manifest when requested.
if args.prune_obsolete and (feed/'manifest.json').exists():
 for item in json.loads((feed/'manifest.json').read_text()):
  if item['file'] not in {m['file'] for m in manifest}:
   old=feed/item['file']
   if old.is_file() and old.parent==feed:old.unlink()
# Preserve other package files unless explicitly recorded as obsolete above.
known={m['file'] for m in manifest}
for p in sorted(feed.glob('*.nupkg')):
 if p.name not in known:manifest.append(dict(file=p.name,bytes=p.stat().st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest()))
(feed/'manifest.json').write_text(json.dumps(sorted(manifest,key=lambda m:m['file']),indent=2)+'\n')
print(f'Bundled {len(manifest)} original NuGet packages')
