# .NET 8 Windows installers

`dotnet/windowsdesktop-runtime-8.0.33-win-x64.exe` is the unmodified Microsoft .NET 8 Windows Desktop Runtime x64 installer. Its SHA-512 was checked against Microsoft's official release metadata. Original URL, size and digest are recorded in `dotnet/origin.json`; digest is also in `dotnet/SHA512SUMS.txt`.

Double-click the EXE on Windows to install. This installer has NOT been executed in the Linux cloud environment. Windows can also show its publisher through Properties → Digital Signatures.

The delivered `SAAM_DAS.exe` is self-contained, so a separate runtime installation is normally unnecessary. This installer is supplied at the user's request for other Windows runtime scenarios. It is not the SDK and does not add Visual Studio build tools.

For source builds install Windows x64 **.NET SDK 8.0.427** and VS2022's .NET desktop development workload: https://dotnet.microsoft.com/download/dotnet/8.0 . Npcap is a separate prerequisite for capture/PCAP reading and is not included here.
