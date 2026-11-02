param([string]$OutputDirectory = "artifacts/windows-x64-net9")
$ErrorActionPreference = "Stop"
$repo = Split-Path $PSScriptRoot -Parent
Push-Location $repo
try {
    if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
        throw "Install Windows x64 .NET SDK 9.0.200 first. The SDK is a prerequisite and is not a NuGet package."
    }
    $sdkVersion = & dotnet --version
    if ($LASTEXITCODE -ne 0 -or $sdkVersion -notmatch '^9\.0\.') {
        throw "This repository requires the .NET 9 SDK selected by global.json (9.0.200). Install the Windows x64 SDK, not only the runtime."
    }
    $manifest = Get-Content "nuget-offline/manifest.json" -Raw | ConvertFrom-Json
    foreach ($item in $manifest) {
        $package = Join-Path "nuget-offline" $item.file
        if ((Get-FileHash $package -Algorithm SHA256).Hash.ToLowerInvariant() -ne $item.sha256) {
            throw "Bundled package hash mismatch: $package"
        }
    }
    dotnet restore src/LanScope/LanScope.csproj --locked-mode --configfile NuGet.Config --packages .nuget/packages --no-cache
    if ($LASTEXITCODE -ne 0) { throw "Offline package restore failed ($LASTEXITCODE)" }
    dotnet publish src/LanScope/LanScope.csproj -c Release -r win-x64 --self-contained false --no-restore -o $OutputDirectory
    if ($LASTEXITCODE -ne 0) { throw "WPF publish failed ($LASTEXITCODE)" }
    Write-Host "Build completed: $OutputDirectory/DRAS.exe"
} finally { Pop-Location }
