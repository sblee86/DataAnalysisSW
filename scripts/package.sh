#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
output_dir="${1:-/workspace/artifacts}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"
cd "$repo_dir"
mkdir -p docs
cp design/ui-preview.html docs/index.html
touch docs/.nojekyll
dotnet restore src/LanScope/LanScope.csproj -r win-x64 --locked-mode
dotnet publish src/LanScope/LanScope.csproj -c Release -r win-x64 --self-contained true --no-restore -o "$output_dir/windows-x64"
python3 - "$repo_dir" "$output_dir" <<'PY'
import sys,zipfile,pathlib
repo,out=map(pathlib.Path,sys.argv[1:])
def pack(root,target,skip):
 with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED) as z:
  for p in sorted(root.rglob('*')):
   rel=p.relative_to(root)
   if p.is_file() and not any(x in skip for x in rel.parts): z.write(p,rel)
pack(repo,out/'LANscope-source.zip',{'.git','bin','obj','.vs','artifacts','downloads'})
pack(out/'windows-x64',out/'LANscope-win-x64.zip',set())
PY
cp design/ui-preview.html "$output_dir/ui-preview.html"
