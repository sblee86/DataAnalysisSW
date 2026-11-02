# Project workflow — current v0.5 contract

- Primary app: Windows WPF, C# 12/.NET 8 (SDK 8.0.427, net8.0-windows). Use the existing checkout; no worktrees unless requested. Preserve unrelated user changes.
- Every delivered revision includes GitHub links to the Windows x64 build ZIP, full repository ZIP (with offline NuGet), and rendered GitHub Pages UI. Internal /workspace download links do not work for this user.
- Windows cross-build uses EnableWindowsTargeting; run actual WPF/DPAPI/Npcap validation on Windows. Never call a Linux build Windows runtime verification.
- Keep design/ui-preview.html and design/icd-csv.js synced to docs/index.html and docs/icd-csv.js with scripts/package.sh. Pages uses main /docs. Web is PUBLIC DEMO ONLY; login admin/admin is explicitly requested for UI review. Windows credentials and vault keys remain separate.
- Bundle required original .nupkg files in nuget-offline/ with hashes; preserve signatures/TLS verification. Full GitHub repository ZIP includes feed; downloads/SAAM_DAS-source.zip is code-only. Exclude .git, caches, bin/obj, credentials and real confidential ICDs from artifacts.

## Roles — user clarification supersedes ALL earlier guest recording restrictions

- BOTH admin and guest record ALL frames Npcap delivers on the SAME configured NICs to standard PCAP, including non-IP and unmatched traffic. No ICD permission filter/BPF may discard recording data. NIC configuration selects devices; each NIC still requires at least one interface mapping.
- All interfaces and their classification counters are visible to both roles. Top counts/bytes measure full NIC records, not sum of overlapping interface matches.
- ONLY admin adds/edits/deletes interfaces/CSV ICDs/IPs, NIC mappings and output paths.
- ICD allowlist applies ONLY to PCAP→CSV value conversion. admin converts all; guest converts explicitly allowed ICDs only. Default deny conversion must NEVER disable PCAP collection.
- Same-NIC/IP ambiguity between permitted and restricted ICDs may block GUEST CSV CONVERSION only, not recording. Message framing/discriminators await actual IDLStudio CSV input.
- App conversion permissions do not prevent external tools from analyzing standard PCAP files. Do not promise OS file access controls, retrospective revocation, or anti-debug security.

## ICD confidentiality and decoding

- Active input is IDLStudio CSV; actual export sample pending. Explicit provisional rules: docs/CSV-ICD.md. All communications BIG ENDIAN; single bytes unchanged. Default msb0 numbering is provisional and separate from endian; explicit lsb0 supported.
- Admin-only import/schema/HEX editing. Encrypt source/filename with AES-GCM under separately derived admin password key. Never persist private keys, plaintext imported ICDs, or real ICDs in repo/Pages. Encrypted demo samples and public verification/recipient keys may be embedded.
- Guest encrypted ICD envelopes use ECDH recipient public key, created ONLY for conversion-allowed ICDs. Guest source decrypts internally only during authorized conversion; no original/schema editor. Exported CSV necessarily exposes permitted field names/values.
- Mutable config is Hidden + DPAPI CurrentUser, with admin signature verified against EXE-pinned public key. New session metadata contains references only, not ICD source/filename/structure. Legacy metadata conversion is admin-only and leaves PCAP unchanged.
- Credential regeneration updates account/public-key/demo resources together. Existing vault key rotation is not implemented: preserve old build/password/source before changing deployed credentials.

## Recording and CSV conversion

- One unique directory per test; one whole-NIC standard PCAP per selected NIC. Interface matches are counters only. Snapshot all original frame bytes before parsing.
- CSV service checks permission independently before creating output and rechecks current signed config at job start. Stream complete matching UDP datagrams into values CSV; TCP reassembly/automatic message discrimination/CDR inference are unsupported. Report skips and field decode errors; never fabricate values.
- Cancellation/failure removes partial temp CSV; never overwrite original PCAP. Keep input and output distinct.
- Test production domain/crypto/recording/conversion classes via tests/LanScope.Checks; secrets via named test bindings, never printed. Windows-specific checks are skipped explicitly in Linux. Web test script for this revision is /workspace/.setup/verify-v05.cjs.

## VS2022 compatibility

- User requires VS2022-compatible sources. Keep app on net8.0-windows and checks on net8.0 with C# 12; do not reintroduce .NET 10 or .slnx. Root SAAM_DAS.sln opens in VS2022 supporting .NET 8 (17.8 family, latest patches; SDK minimum MSBuild 17.8.3).
- Global SDK 8.0.427 and offline Windows runtime/reference packs 8.0.33 are matched. Current feed has 11 original packages including transitive dependencies. Use SDK 8 for all validation, Debug solution build and Windows self-contained publish.
- Preserve account, policy and guest recipient keys during framework migration. Verify existing encrypted resources/public keys with .NET 8 checks before delivery. Windows executable is self-contained and does not require the SDK for running.

## SAAM_DAS branding and UI

- Display/product/executable name is SAAM_DAS (Data analysis software), also called DAS. Keep RootNamespace=LanScope and cryptographic derivation strings unchanged to preserve keys. Old workspace.bin location remains LANscope; new non-secret UI preference file is SAAM_DAS/ui-preferences.bin.
- Solution is SAAM_DAS.sln; executable SAAM_DAS.exe; delivery ZIPs downloads/SAAM_DAS-source.zip and SAAM_DAS-win-x64.zip. Public repo remains sblee86/DataAnalysisSW.
- Navigation must remain high-contrast in normal/selected/hover/disabled states. Do not force a global TextBlock.Foreground that overrides button text inheritance.
- Upper-right screen settings offers font size 12..18 (default 13) for both roles, persisted separately from admin-only configuration. Scale fixed rows/heights with fonts.
- Context delete is admin-only and blocked while recording/busy: profiles delete with confirmation, NIC mappings clear, dashboard single mappings remove. PCAP path clear is non-destructive and available to both roles. Never delete capture files through these actions.

## Runtime installer and bit write support

- User requested the .NET runtime installer. Include the unmodified official Windows Desktop Runtime 8.0.33 win-x64 EXE under installers/dotnet with verified Microsoft SHA-512, source metadata and clear SDK-vs-runtime instructions. The single app EXE remains self-contained.
- CSV interface import/save is admin-only and seals raw definitions in the encrypted internal store. Never introduce plaintext exported ICD config near the executable.
- Bit fields support BOTH reading and writing. WriteValue/Encode preserve all bits outside the selected field, including cross-byte msb0/lsb0 ranges. Default writes inverse-scale engineering values; raw mode uses raw integers and IEEE754 unsigned bit patterns for floats. Range/length errors must not partially mutate caller data. This is payload buffer construction, not live transmission.
