# ApkSpy: top 30 missing features (research, 2026-11)

Sources: jadx's issue tracker (most-discussed open requests), jadx / JEB /
GDA / Bytecode Viewer feature lists, MobSF's static-analysis feature set,
HackTricks' APK decompiler page, and the tool round-ups people link to in
reverse-engineering discussions. Reddit search turned up almost nothing
directly, so the "community" signal is mostly the jadx tracker and tool
comparisons.

Excluded on purpose (out of scope for this project): anything that
rebuilds, re-signs, aligns or installs an APK; Frida integration; any
extension of HTTPS decryption; pinning / root-detection / anti-tamper
bypasses; unpacking protected apps. Packers are *detected* only.

Status: **done** = implemented in this change, **-** = not started.

| #  | Feature | Why people ask for it | Status |
|----|---------|-----------------------|--------|
| 1  | Hard-coded secret scanner (AWS, Google, Firebase, GitHub, Slack, Stripe, private keys, JWTs...) | MobSF's most-used static check | **done** |
| 2  | Tracker / third-party SDK detection | MobSF trackers, Exodus-style reports | **done** |
| 3  | Framework detection (Flutter, React Native / Hermes, Xamarin, Unity, Cordova, Compose...) | Decides which tool to use next | **done** |
| 4  | Packer / protector detection (detection only) | First question in every triage | **done** |
| 5  | Code-risk rules (WebView JS bridge, weak crypto, insecure TLS trust managers, dynamic code loading, world-readable files, SQL raw queries...) with caller locations | MobSF / mobsfscan rules | **done** |
| 6  | Obfuscation estimate | Triage | **done** |
| 7  | Manifest audit in the UI (it only existed over MCP) | Attack surface at a glance | **done** |
| 8  | SARIF / JSON export of findings | CI and ticketing | **done** |
| 9  | ProGuard / R8 mapping.txt import + stack-trace retrace | jadx supports mappings; crash triage | **done** (parser + retrace) |
| 10 | Edit validation, export, per-file diff report | ApkSpy brief features 1-3 | **done** |
| 11 | Apply mapping.txt names in the class tree and decompiler | jadx mapping support | - |
| 12 | Rename classes / methods / fields (not just variables) and export as mapping | jadx #1590, Super JADX | - |
| 13 | Persist edits (incl. in-memory smali edits) in the project file | Edits are lost on exit today | - |
| 14 | Resource ID annotation in smali / decompiler (0x7f... -> R.string.name) | Readability | - |
| 15 | Exclusion rules: hide library packages from search and analysis | jadx #2152 | - |
| 16 | Deep link / intent-filter list with copyable `adb am start` commands | Pentest workflow | - |
| 17 | Permission -> API usage map (where each dangerous permission is used) | MobSF | - |
| 18 | AAB / XAPK / APKS bundle opening | Store downloads are bundles | - |
| 19 | DEX v41 (container format) support | jadx #2128 | - |
| 20 | Theme follows the system light / dark setting | jadx #2279 | - |
| 21 | Customisable keyboard shortcuts | jadx #1479 | - |
| 22 | Sensitive-logging finder (Log.* with user data) | MobSF | partial (rule counts Log calls) |
| 23 | Native: list JNI_OnLoad / RegisterNatives tables mapped to Java natives | Native RE | - |
| 24 | String decryption helper (run a selected pure decoder on constant args, static only) | Obfuscated apps | - |
| 25 | Switch-over-strings and nested-structure clean-up in the built-in decompiler | jadx #2278, #2180 | - |
| 26 | Per-method smali diff between two APK versions | Patch analysis | - |
| 27 | Network-security-config viewer (pins, cleartext domains) | MobSF | partial (audit flags it) |
| 28 | Firebase / backend endpoint inventory linked to code | Recon | partial (secrets + endpoints) |
| 29 | Bookmarks / notes export to Markdown | Reporting | - |
| 30 | Plugin enable/disable and storage for scripts | jadx #2277, #2188 | - |
