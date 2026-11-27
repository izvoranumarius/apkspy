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
| 11 | Apply mapping.txt names to the class tree and search | **done** (class tree shows `obf -> original`; the built-in Java output uses the original class, method and field names) |
| 12 | Rename classes / methods / fields | **done** for the decompiler: symbol and variable renames, exported as a Markdown table or (symbols only) as a ProGuard `mapping.txt` (Bookmarks > Export mapping). Renames of names a loaded mapping.txt gave are exported against the app's own names |
| 13 | Persist edits in the project file | **done** |
| 14 | Resource ids in smali (`0x7f...` -> `@string/name`) | **done** (smali listings; the built-in Java output shows `R.type.name`) |
| 15 | Hide library packages from the class tree | **done** (Analysis > Hide libs, editable prefix list) |
| 16 | Deep links with copyable `adb am start` commands | **done** (Insights > Manifest) |
| 17 | Permission -> API usage map, and guarded APIs used without the permission | **done** |
| 18 | XAPK / APKS / APKM bundles | **done** (base + code/native splits), and **AAB** (manifest and resource table converted, one APK per module; checked against `aapt2` output, not yet a bundle from a store) |
| 19 | DEX v41 (container format) | **done** (one DexFile per container section) |
| 20 | Theme follows the system light / dark setting | **done** (Windows; other platforms report "unknown") |
| 21 | Customisable keyboard shortcuts | **done** for the global shortcuts (Settings > Keyboard). Editor keys, debugger F-keys, zoom and Ctrl+1..5 stay fixed |
| 22 | Sensitive-logging finder | **done** as a heuristic (Insights > Code risks): log calls rated by the data followed into the message (through string building, app methods, callers, fields written elsewhere and collections) and by the names around them; native code and reflection are not followed |
| 23 | JNI RegisterNatives tables mapped to natives | **done** (Analysis > Native > JNI > Registered natives; RELA and RELR relocations). Validated on synthetic libraries only: the one real library available registers its natives at run time |
| 24 | String decryption helper | **done**: Insights > Decoded lists encoded constants, and runs an app's own static decoders in a sandboxed interpreter (try / catch, reflection, objects of app classes, floating point, java.util collections, AES / DES / RSA including OAEP and public-key encryption, GCM, digests). Not emulated: I/O and library classes outside that list |
| 25 | Switch-over-strings and nested-structure clean-up in the built-in decompiler | **partial**: `switch (s) { case "a": ... }` is recovered for the javac/D8 (hash switch, equals, index, second switch) and kotlinc (direct) shapes: 80 of 117 such methods in one large app, 27 of 44 in another, versus 9 and 0 before. Odd shapes stay as the hash switch. Nested ifs are flattened (`&&`, `else if`, no `else` after a return) |
| 26 | Per-method smali diff between two APK versions | **done** (Analysis > Compare: click a changed method) |
| 27 | Network-security-config viewer | **done** (Insights > Manifest) |
| 28 | Backend endpoint inventory | **done** (Insights > Endpoints: hosts grouped, cloud backends classified, links to code) |
| 29 | Bookmarks / notes export to Markdown | **done** |
| 30 | Plugin enable / disable for scripts | **done** (per-script switches for traffic scripts, and scripts that run when ApkSpy starts) |
