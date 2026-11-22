# ApkSpy: top 30 missing features (research, 2026-11)

Sources: jadx's issue tracker (most-discussed open requests), jadx / JEB /
GDA / Bytecode Viewer feature lists, MobSF's static-analysis feature set,
HackTricks' APK decompiler page, and the tool round-ups people link to in
reverse-engineering discussions. Reddit search turned up almost nothing
directly, so the "community" signal is mostly the jadx tracker and tool
comparisons.

Excluded on purpose: anything that extends HTTPS decryption, pinning /
root-detection / anti-tamper bypasses, and unpacking protected apps.
Packers are *detected* only.

Status: **done** = implemented, **partial** = part of it exists, **-** = not
started (with the reason).

| #  | Feature | Status |
|----|---------|--------|
| 1  | Hard-coded secret scanner (AWS, Google, Firebase, GitHub, Slack, Stripe, private keys, JWTs...) | **done** (Insights > Secrets) |
| 2  | Tracker / third-party SDK detection | **done** (Insights > SDKs) |
| 3  | Framework detection (Flutter, React Native / Hermes, Xamarin, Unity, Cordova, Compose...) | **done** |
| 4  | Packer / protector detection (detection only) | **done** |
| 5  | Code-risk rules (WebView bridges, weak crypto, insecure TLS, dynamic code loading...) with callers and constant arguments | **done** |
| 6  | Obfuscation estimate | **done** |
| 7  | Manifest audit in the UI (was MCP-only) | **done** (Insights > Manifest) |
| 8  | SARIF / JSON / Markdown export of findings | **done** |
| 9  | ProGuard / R8 mapping.txt import and stack-trace retrace | **done** (Insights > Retrace) |
| 10 | Edit validation, export of edited files, per-file diff report | **done** (Edits panel) |
| 11 | Apply mapping.txt names to the class tree and search | **done** (class tree shows `obf -> original`; the decompiler output is not rewritten) |
| 12 | Rename classes / methods / fields | **partial**: symbol and variable renames existed in the decompiler; they now export as a Markdown rename table (Bookmarks > Export MD). No ProGuard-format export: renames are identifier-level, not descriptor-level |
| 13 | Persist edits in the project file | **done** |
| 14 | Resource ids in smali (`0x7f...` -> `@string/name`) | **done** (smali listings; not yet the decompiler) |
| 15 | Hide library packages from the class tree | **done** (Analysis > Hide libs, editable prefix list) |
| 16 | Deep links with copyable `adb am start` commands | **done** (Insights > Manifest) |
| 17 | Permission -> API usage map, and guarded APIs used without the permission | **done** |
| 18 | XAPK / APKS / APKM bundles | **done** (base + code/native splits). **AAB: not done** - its manifest is protobuf, not AXML |
| 19 | DEX v41 (container format) | **done** (one DexFile per container section) |
| 20 | Theme follows the system light / dark setting | **done** (Windows; other platforms report "unknown") |
| 21 | Customisable keyboard shortcuts | **done** for the global shortcuts (Settings > Keyboard). Editor keys, debugger F-keys, zoom and Ctrl+1..5 stay fixed |
| 22 | Sensitive-logging finder | **partial**: the logging rule lists every Log / println / printStackTrace caller with the constant arguments it passes |
| 23 | JNI RegisterNatives tables mapped to natives | **done** (Analysis > Native > JNI > Registered natives; RELA and RELR relocations). Validated on synthetic libraries only: the one real library available registers its natives at run time |
| 24 | String decryption helper | **partial**: Insights > Decoded lists base64 / hex / URL-encoded constants that decode to text. Running an app's own decryption routine is not done (it would mean executing app code) |
| 25 | Switch-over-strings and nested-structure clean-up in the built-in decompiler | - (a decompiler rewrite, not an incremental change) |
| 26 | Per-method smali diff between two APK versions | **done** (Analysis > Compare: click a changed method) |
| 27 | Network-security-config viewer | **done** (Insights > Manifest) |
| 28 | Backend endpoint inventory | **done** (Insights > Endpoints: hosts grouped, cloud backends classified, links to code) |
| 29 | Bookmarks / notes export to Markdown | **done** |
| 30 | Plugin enable / disable for scripts | - (ApkSpy has no plugin system to switch) |
