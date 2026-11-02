# LANscope

Windows LAN packet capture / raw packet storage / analysis workspace. Initial release is a **WPF UI prototype**, with a matching standalone HTML review page. Live capture and loading user capture files are not implemented yet.

## Windows test

Extract the self-contained Windows x64 build ZIP and run `LanScope.exe`. No separate .NET installation is needed. Windows 10/11 x64 is the target; the executable has been cross-built on Linux, but has not been run on Windows here.

- Select a demo packet to inspect its illustrative details.
- Search IP / protocol / text. Reset reloads sample rows.
- “샘플 PCAP 저장” writes **one separate synthetic UDP frame**, not the eight illustrative table rows. Open that file in Wireshark to inspect the Ethernet/IPv4/UDP payload `TEST`. The frame is synthetic and includes placeholder checksums.
- The raw hex panel shows that separate synthetic frame, not bytes from the selected table row.
- Npcap is required later for Windows live capture, not for the current UI prototype.

## Build

.NET SDK 10.0.403 or compatible .NET 10 SDK:

```sh
dotnet restore src/LanScope/LanScope.csproj -r win-x64 --locked-mode
dotnet publish src/LanScope/LanScope.csproj -c Release -r win-x64 --self-contained true --no-restore -o artifacts/windows-x64
```

Linux builds use `EnableWindowsTargeting` from the project. WPF cannot run on Linux. NuGet packages: SharpPcap 6.3.1, PacketDotNet 1.4.8 (prepared for later capture integration).

## UI review

Open `design/ui-preview.html` directly in a browser. No server or external resources are needed. It uses the same content, colors and panel hierarchy as WPF; native control/font rendering will vary. The page is a review mockup, not a browser packet sniffer. Data selection, search, reset and synthetic PCAP download work locally.

## Deliverables

`scripts/package.sh` publishes the Windows x64 executable and creates source/build ZIP files in the supplied output directory (default `/workspace/artifacts`). Every delivered revision should include both ZIP links and the standalone HTML preview link.

## GitHub downloads

- [Windows x64 build ZIP](https://github.com/sblee86/DataAnalysisSW/raw/refs/heads/main/downloads/LANscope-win-x64.zip)
- [Source ZIP](https://github.com/sblee86/DataAnalysisSW/raw/refs/heads/main/downloads/LANscope-source.zip)
- [Live UI preview (GitHub Pages)](https://sblee86.github.io/DataAnalysisSW/)
- [HTML preview source](design/ui-preview.html)

The downloadable Windows build is a UI prototype; live capture is not implemented.

## GitHub Pages

The site entry point is `docs/index.html`, an exact copy of `design/ui-preview.html`. Packaging synchronizes the two.

One-time repository setting: **Settings → Pages → Build and deployment → Deploy from a branch → main → /docs → Save**. GitHub then publishes the preview at https://sblee86.github.io/DataAnalysisSW/ and updates it when `docs/` changes on main. Repository Pages activation and public HTTP access have not been verified from the cloud because api.github.com and sblee86.github.io are blocked by its outbound policy.
