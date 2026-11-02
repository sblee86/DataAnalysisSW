# Project workflow

- Primary application: Windows WPF, C#/.NET 10. Use the existing checkout; no extra worktrees unless requested.
- For each delivered revision, build the WPF Windows x64 app and provide a downloadable repository ZIP and build ZIP. Be explicit about untested Windows runtime behavior.
- Maintain design/ui-preview.html with the same colors, layout, labels and screen states as the WPF UI. Deliver its HTML link for user review, plus a screenshot when available.
- Mark demonstration data clearly; never imply real capture works unless implemented and verified on Windows with Npcap.
- Build in Linux using EnableWindowsTargeting=true; run WPF and live Npcap validation on Windows. Offline packet analysis can be tested in Linux.
- Do not include .git, build caches or credentials in source ZIPs. Include source, lockfiles, documentation and preview.

- User needs accessible GitHub links; internal /workspace file links did not work. When authorized to publish a delivery, upload artifacts to GitHub and verify remote files, then provide GitHub download links. Exclude downloads/ from packaged source ZIP to avoid recursive archives.

- UI review must open as a website via GitHub Pages at https://sblee86.github.io/DataAnalysisSW/ . Keep docs/index.html byte-identical to design/ui-preview.html and publish docs/ on main. Do not substitute a GitHub source-view link for a rendered preview. Distinguish uploaded Pages source from verified live publication.
- Include all required NuGet .nupkg files in nuget-offline/ (including Windows host, reference and self-contained runtime packs) with a SHA-256 manifest. Preserve original package signatures. Verify restore with an empty package cache and only the local feed. Windows users build via scripts/build-offline.ps1 after installing the pinned SDK.
- Full repository ZIP from GitHub includes the offline NuGet feed. downloads/LANscope-source.zip is code-only to stay within GitHub's per-file limit; label it accordingly.

## v0.2 application contract

- admin: profile/ICD/IP settings, NIC matching, output directory, recording start/stop and monitoring. guest: recording start/stop and monitoring; no configuration mutation. Enforce permissions in settings services as well as visibility.
- Store salted PBKDF2 hashes in embedded Resources/accounts.bin; never add plaintext account passwords to source/configuration. Account regeneration prompts securely via scripts/set-accounts.py. Include resources in the single Windows EXE.
- Mutable workspace settings are a Hidden binary file in Windows LocalAppData, encrypted with DPAPI CurrentUser. Never silently reset corrupt settings. Both app roles share that Windows user's configuration.
- Match individual IPv4/IPv6 sender/receiver addresses; optional reverse flow. At least one profile is required per enabled NIC. Each test creates a unique directory and one PCAP per NIC/profile. Session metadata includes the original ICD in binary form.
- Sample ICDs are hand-written OMG IDL examples, not verified IDLStudio exports. Current capture matching is IP-based; do not claim IDL payload decoding.
- Keep the HTML preview aligned with login, roles, profile/settings screens and monitoring. Browser NICs/recording are clearly labeled simulations. Live Windows capture and DPAPI require Windows verification.
- Run tests/LanScope.Checks with password test bindings for the delivered temporary accounts; never log them. Windows-specific tests must be reported skipped when run on Linux.

## v0.3 CSV ICD contract

- Active ICD input is IDLStudio CSV. Actual export sample is pending; never claim verified IDLStudio compatibility. Explicit provisional schema is in docs/CSV-ICD.md.
- Communication is BIG ENDIAN ONLY. Single-byte values stay unchanged. Reject explicit little endian; default bit numbering is provisional msb0, with explicit lsb0 option independent from byte order.
- CSV import validates the field layout and shows payload HEX decode preview (including signed and cross-byte bit fields). Live capture still matches IP endpoints; no automatic message framing/CDR/TCP reconstruction. Preserve old IDL config until the admin explicitly replaces it with CSV.
- Keep design/icd-csv.js and the C# parser consistent; package.sh copies JS alongside docs/index.html. Revalidate sample vectors and both role workflows after UI changes.
