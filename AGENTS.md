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
