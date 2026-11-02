# Project workflow

- Primary application: Windows WPF, C#/.NET 10. Use the existing checkout; no extra worktrees unless requested.
- For each delivered revision, build the WPF Windows x64 app and provide a downloadable repository ZIP and build ZIP. Be explicit about untested Windows runtime behavior.
- Maintain design/ui-preview.html with the same colors, layout, labels and screen states as the WPF UI. Deliver its HTML link for user review, plus a screenshot when available.
- Mark demonstration data clearly; never imply real capture works unless implemented and verified on Windows with Npcap.
- Build in Linux using EnableWindowsTargeting=true; run WPF and live Npcap validation on Windows. Offline packet analysis can be tested in Linux.
- Do not include .git, build caches or credentials in source ZIPs. Include source, lockfiles, documentation and preview.

- User needs accessible GitHub links; internal /workspace file links did not work. When authorized to publish a delivery, upload artifacts to GitHub and verify remote files, then provide GitHub download links. Exclude downloads/ from packaged source ZIP to avoid recursive archives.
