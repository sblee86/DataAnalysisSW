# Project workflow — current DRAS contract

- Primary app: Windows WPF, C# 12/ .NET 9 (SDK 9.0.200, net9.0-windows). Use the existing checkout; no worktrees unless requested. Preserve unrelated user changes.
- Every delivered revision includes GitHub links to the Windows x64 build ZIP, full repository ZIP (with offline NuGet), and rendered GitHub Pages UI. Internal /workspace download links do not work for this user.
- Windows cross-build uses EnableWindowsTargeting; run actual WPF/DPAPI/Npcap validation on Windows. Never call a Linux build Windows runtime verification.
- Keep design/ui-preview.html and design/icd-csv.js synced to docs/index.html and docs/icd-csv.js with scripts/package.sh. Pages uses main /docs. Web is PUBLIC DEMO ONLY; login admin/admin is explicitly requested for UI review. Windows credentials and vault keys remain separate.
- Bundle required original .nupkg files in nuget-offline/ with hashes; preserve signatures/TLS verification. Full GitHub repository ZIP includes feed; downloads/DRAS-source.zip is code-only. Exclude .git, caches, bin/obj, credentials and real confidential ICDs from artifacts.

## Roles — user clarification supersedes ALL earlier guest recording restrictions

- BOTH admin and guest record ALL frames Npcap delivers on the SAME configured NICs to standard PCAP, including non-IP and unmatched traffic. No ICD permission filter/BPF may discard recording data. NIC configuration selects devices; each NIC still requires at least one interface mapping.
- All interfaces and their classification counters are visible to both roles. Top counts/bytes measure full NIC records, not sum of overlapping interface matches.
- ONLY admin adds/edits/deletes interfaces/CSV ICDs/IPs, NIC mappings and output paths.
- ICD allowlist applies ONLY to PCAP→CSV value conversion. admin converts all; guest converts explicitly allowed ICDs only. Default deny conversion must NEVER disable PCAP collection.
- Same-NIC/IP ambiguity between permitted and restricted ICDs may block GUEST CSV CONVERSION only, not recording. Message framing/discriminators await actual IDLStudio CSV input.
- App conversion permissions do not prevent external tools from analyzing standard PCAP files. Do not promise OS file access controls, retrospective revocation, or anti-debug security.

## ICD confidentiality and decoding

- Active input is IDLStudio CSV; actual export sample pending. Explicit provisional rules: docs/CSV-ICD.md. Per-profile csv/be/le selectable; default per-field be, single bytes unchanged. Default msb0 numbering is provisional and separate from endian; explicit lsb0 supported.
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

- User requires VS2022-compatible sources. Keep app on net9.0-windows and checks on net9.0 with C# 12; do not reintroduce .NET 10 or .slnx. Root DRAS.sln opens in VS2022 supporting  .NET 9 (17.12 family, latest patches; SDK minimum MSBuild 17.12.0).
- Global SDK 9.0.200 and offline Windows runtime/reference packs 9.0.2 are matched. Current feed has 7 original packages including transitive dependencies. Use SDK 9 for all validation, Debug solution build and Windows framework-dependent publish.
- Preserve account, policy and guest recipient keys during framework migration. Verify existing encrypted resources/public keys with  .NET 9 checks before delivery. Windows app is framework-dependent, needs Desktop Runtime9.0.2+, and all app ZIP files must stay together. No SDK is needed just for running.

## DRAS branding and UI

- Display/product/executable name is DRAS (Data Recording & analysis software), also called DAS. Keep RootNamespace=LanScope and cryptographic derivation strings unchanged to preserve keys. Old workspace.bin location remains LANscope; new non-secret UI preference file is DRAS/ui-preferences.bin.
- Solution is DRAS.sln; executable DRAS.exe; delivery ZIPs downloads/DRAS-source.zip and DRAS-win-x64.zip. Public repo remains sblee86/DataAnalysisSW.
- Navigation must remain high-contrast in normal/selected/hover/disabled states. Do not force a global TextBlock.Foreground that overrides button text inheritance.
- Upper-right resizable screen settings offers independent Body/Menu/Table/TableHeader/Title fonts (13/13/12/12/28 defaults) and draggable ICD/NIC pane widths for both roles, persisted separately from admin configuration. Scale fixed rows/heights with fonts.
- Context delete is admin-only and blocked while recording/busy: profiles delete with confirmation, NIC mappings clear, dashboard single mappings remove. PCAP path clear is non-destructive and available to both roles. Never delete capture files through these actions.

## Runtime installer and bit write support

- User requested the .NET runtime installer. Include the unmodified official Windows Desktop Runtime 9.0.2 win-x64 EXE under installers/dotnet with verified Microsoft SHA-512, source metadata and clear SDK-vs-runtime instructions. Do not bundle the runtime inside the app; the official installer is the only runtime install artifact.
- CSV interface import/save is admin-only and seals raw definitions in the encrypted internal store. Never introduce plaintext exported ICD config near the executable.
- Bit fields support BOTH reading and writing. WriteValue/Encode preserve all bits outside the selected field, including cross-byte msb0/lsb0 ranges. Default writes inverse-scale engineering values; raw mode uses raw integers and IEEE754 unsigned bit patterns for floats. Range/length errors must not partially mutate caller data. This is payload buffer construction, not live transmission.

## External headers and active catalog

- Import restricted .h/.hpp declarations alongside CSV, never execute C/preprocessor or load includes. Explicit pack1/2/4/8 and storage-unit lsb0/msb0; this is not automatic compiler ABI detection. See docs/CSV-ICD.md.
- Seal header names/bytes with CSV in IcdBundle; preserve legacy CSV-only fingerprint/envelopes and account resources. StructSources and raw names/content must remain JsonIgnore. Guest recipient bundle contains only authorized ICDs and is parsed internally for conversion.
- Enabled state is signed profile metadata. Disabled ICDs do not classify/convert, but full NIC PCAP recording and mappings persist for both roles.
- Keep design/c-struct.js copied to docs/c-struct.js and artifacts alongside icd-csv.js. Run tests/check-csv-web.cjs and tests/check-ui.cjs (Playwright, CHROMIUM_PATH optional, guest password via named test binding).

## Administrator ICD export (explicitly authorized)

- Admin may explicitly export plaintext ICD definitions to a chosen CSV/ZIP location. This supersedes any earlier blanket ban on exported plaintext ICDs; internal storage remains encrypted and no exports happen automatically. Guest CSV value conversion grants never grant ICD-definition/header export.
- IcdExport.Csv/Package enforce RequireAdmin before reading/decrypting source. Export current editor or encrypted saved profile without modifying its ciphertext/plaintext state. ZIP contains normalized Excel CSV, exact original CSV/header bytes, import options and generated C++17 wire-buffer/raw accessor structs. No accounts, keys, config or PCAP.
- Canonical CSV storage_bits/storage_bit_offset/message_size preserve struct bit storage/endian/tail padding on standalone reimport. Original header editing roundtrip uses original/source.csv plus original/headers and original options. Generated dras-wire.hpp is integration code, not restricted importer input. Never silently claim compiler-native bitfield layout equivalence.
- Keep design/icd-export.js synced to docs/icd-export.js and delivery preview assets. Test admin/guest authorization, Excel-style edit/reimport, both endians/bit orders, header fidelity, safe ZIP paths, and generated C++ compile/read/write.

## Plain C++ struct export and folding UI

- User clarified C++ export means ordinary `struct Name { uint16_t member; uint8_t flag : 3; float value; };`, not only a wire-buffer/helper API. IcdExport.Struct enforces admin and exports icd-struct.hpp directly; ZIP also includes it. Native ABI is not the exact ICD wire layout. Preserve wire metadata in comments/CSV; do not claim generated declarations serialize network endian automatically.
- Five independently collapsible WPF Expanders / web details sections: import, export, fields, HEX, endpoints/permissions. Import/endpoints open initially; samples are a subordinate fold. Export is one format selector (CSV/C++/ZIP) and one button; default C++ struct. Folding must retain inputs and role locks.

## Current SDK9 and tab UI contract supersedes old folding/self-contained notes

- User has SDK9.0.200; global.json selects it. App/checks target net9; runtime9.0.2 maps to that SDK. VS2022 minimum17.12. Package framework-dependent EXE+DLL/deps/runtimeconfig; not a single EXE. Keep only seven required original offline packages and one Desktop Runtime9.0.2 installer; no old8 runtime packs/installers.
- Settings title is simply 설정, with 글자 크기 / 배치·입력란 / 계정·보안 tabs. Independent TestNameFont/Width/Height persist in DRAS-UI-3, migrate old UI preferences. Trial input is on an auto-height panel with resize thumb and visible padding, folder-change button admin-only and blocked during capture.
- ICD uses Current/Import/Export/HEX tabs, first current ICD; import splits sources and parse options into cards. Retain fields while switching tabs. All buttons have tooltips explaining purpose and material impact.
- AdminCredentials wraps the EXISTING root key under the new password, verifies current password and pins its signature to old public key. Signed workspace AdminCredentialDigest commits active envelope; hash-named pending allows crash recovery. Missing/corrupt active envelope must never fall back to embedded password. Root key and existing encrypted ICDs/public resource pins remain unchanged. This changes app login, not OS controls or retroactive revocation of leaked keys. Back up workspace and credentials together.
- Public web password changes last only this page session; reload resets admin/admin. Actual credential changes are WPF-only persisted encrypted envelopes.
