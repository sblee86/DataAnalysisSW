#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
output_dir="${1:-/workspace/artifacts}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"
cd "$repo_dir"
mkdir -p docs
cp design/ui-preview.html docs/index.html
cp design/icd-csv.js docs/icd-csv.js
touch docs/.nojekyll
dotnet restore src/LanScope/LanScope.csproj -r win-x64 --locked-mode
publish_dir="$(mktemp -d "$output_dir/.publish-XXXXXX")"
trap 'rm -rf "$publish_dir"' EXIT
dotnet publish src/LanScope/LanScope.csproj -c Release -r win-x64 --self-contained true --no-restore -o "$publish_dir"
python3 - "$repo_dir" "$output_dir" "$publish_dir" <<'PY'
import sys,zipfile,pathlib
repo,out,publish=map(pathlib.Path,sys.argv[1:])
def pack(root,target,skip):
 with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED) as z:
  for p in sorted(root.rglob('*')):
   rel=p.relative_to(root)
   if p.is_file() and not any(x in skip for x in rel.parts): z.write(p,rel)
pack(repo,out/'SAAM_DAS-source.zip',{'.git','bin','obj','.vs','artifacts','downloads','.nuget','nuget-offline','__pycache__','installers'})
pack(publish,out/'SAAM_DAS-win-x64.zip',set())
PY
cp design/ui-preview.html "$output_dir/ui-preview.html"
cp design/icd-csv.js "$output_dir/icd-csv.js"
