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
cp design/c-struct.js docs/c-struct.js
cp design/icd-export.js docs/icd-export.js
touch docs/.nojekyll
dotnet restore src/LanScope/LanScope.csproj --locked-mode
publish_dir="$(mktemp -d "$output_dir/.publish-XXXXXX")"
trap 'rm -rf "$publish_dir"' EXIT
dotnet publish src/LanScope/LanScope.csproj -c Release -r win-x64 --self-contained false --no-restore -o "$publish_dir"
cat > "$publish_dir/READ-ME.txt" <<'INFO'
DRAS - .NET 9 Windows x64
Keep all extracted files together, then run DRAS.exe.
Requires Windows Desktop Runtime 9.0.2 or a newer 9.0.x and Npcap for NIC capture.
The full repository ZIP includes only the official Desktop Runtime 9.0.2 installer:
installers/dotnet/windowsdesktop-runtime-9.0.2-win-x64.exe
Source builds use SDK9.0.200 and VS2022 17.12+.
https://github.com/sblee86/DataAnalysisSW
INFO
python3 - "$repo_dir" "$output_dir" "$publish_dir" <<'PY'
import sys,zipfile,pathlib
repo,out,publish=map(pathlib.Path,sys.argv[1:])
def pack(root,target,skip):
 with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED) as z:
  for p in sorted(root.rglob('*')):
   rel=p.relative_to(root)
   if p.is_file() and not any(x in skip for x in rel.parts): z.write(p,rel)
pack(repo,out/'DRAS-source.zip',{'.git','bin','obj','.vs','artifacts','downloads','.nuget','nuget-offline','__pycache__','installers'})
pack(publish,out/'DRAS-win-x64.zip',set())
PY
cp design/ui-preview.html "$output_dir/ui-preview.html"
cp design/icd-csv.js "$output_dir/icd-csv.js"
cp design/c-struct.js "$output_dir/c-struct.js"
cp design/icd-export.js "$output_dir/icd-export.js"
