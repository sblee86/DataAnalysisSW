# Windows Desktop Runtime 9.0.2 x64

Only `dotnet/windowsdesktop-runtime-9.0.2-win-x64.exe` is included. It is the original Microsoft installer associated with SDK 9.0.200. The SHA-512 was verified against official .NET 9 release metadata; source URL and hash are in `origin.json` and `SHA512SUMS.txt`.

DRAS now targets net9.0-windows and is framework-dependent. Keep all files from the app ZIP together, install Desktop Runtime 9.0.2 or a newer 9.0.x if absent, then launch DRAS.exe. SDK 9.0.200 is needed for source builds; this runtime installer is not an SDK or a Visual Studio workload. VS2022 must be 17.12 or later. Npcap remains a separate capture prerequisite.

The previous .NET 8 installer and embedded-runtime packages were removed. The installer was hash-verified, not executed on Linux.
