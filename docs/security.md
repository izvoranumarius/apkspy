# Security

The **Security** workspace (the last one in the workspace switcher) reviews an
APK for security issues and lists the third-party code it bundles. Both
panels work on the APK selected at the top. They start on their own and run
in the background. The bytecode checks wait for the analysis, and the panel
scans again once it is ready.

## Security scanner

Each finding has a **severity** (Critical, High, Medium, Low, Info) and a
**confidence**. The confidence says how sure the rule is that it found the
issue it describes, not how exploitable that issue is. Each finding also
shows the evidence it saw, its location, a CWE number, an OWASP MASVS
category and a recommendation.

| Category | Checks |
| --- | --- |
| Secrets | AWS, Google, Stripe, Slack, GitHub, SendGrid, Mailgun, Twilio and Firebase server keys, JWTs and PEM private keys in the code's strings, `res/values` strings and bundled text files (`assets/`, `res/raw/`); resource strings named like secrets; key stores (`.jks`, `.bks`, `.p12`...) shipped in the APK. Evidence is masked. |
| Manifest | `debuggable`, `testOnly`, `allowBackup` (including the default when it is missing), `usesCleartextTraffic`, an outdated target SDK |
| Network | network security configuration: cleartext for all or some domains, user-installed CAs trusted outside `<debug-overrides>`; `http://` URLs in the code, by host; TrustManagers that accept every certificate; HostnameVerifiers that accept every host |
| Components | exported activities, services, receivers and providers without a permission (taking the platform defaults for intent filters and providers into account), components guarded by a `normal` or `dangerous` permission, `grantUriPermissions`, PendingIntents without `FLAG_IMMUTABLE` (which throw on Android 12+ for apps targeting API 31) |
| Cryptography | ECB mode (including a bare `"AES"`), DES / 3DES / RC4 / RC2 / Blowfish, MD5 and SHA-1, keys and IVs made from string constants, `SecureRandom.setSeed` with a constant |
| WebView | `onReceivedSslError` calling `proceed()`, `addJavascriptInterface`, JavaScript enabled, file access from file URLs, `setWebContentsDebuggingEnabled(true)`, mixed content always allowed |
| Storage | `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE`, shared external storage |
| Code | SQL built at runtime, passwords and tokens in log messages, `Runtime.exec` / `ProcessBuilder`, `DexClassLoader` and other dynamic code loading |

Constants are traced to the call that uses them. For example, `getInstance`
is only reported as weak when the string reaching it names a weak algorithm,
and `getSharedPreferences(name, mode)` is checked whatever the receiver class
(the app's own Activity included).

Findings in bundled libraries (OkHttp, ad SDKs, Firebase... about 140 are
recognised) name the library, and **Hide library code** leaves them out so
the app's own code can be reviewed first. Use the severity check boxes, the
category list and the filter to narrow the list. Click a finding for its
details, and double-click it (or its location) to open it:

- code opens jadx's Java at the line of the instruction (see
  [Java and smali side by side](analysis.md#java-and-smali-side-by-side)),
  or the smali listing at the instruction when there is no Java;
- manifest findings open `AndroidManifest.xml` at the component or attribute;
- files open at the line, and resource strings print their value in Output.

**Export** writes the report as Markdown or JSON. MCP clients run the same
scan with `security_scan`, which can filter by minimum severity, category and
library code.

## Dependencies

**Dependencies** lists the libraries and frameworks the APK bundles. They are
found three ways: by their package names, by the version files Gradle and
Maven leave in `META-INF/` (`*.version`, `maven/<group>/<artifact>/pom.properties`),
and by their native libraries (`libflutter.so`, `libhermes.so`,
`libil2cpp.so`...). Shrinking and obfuscation can hide packages. Version
files usually survive, so most AndroidX, Kotlin and Firebase versions are
known.

- **Table**: version, category, license and the share of the app's classes,
  with known vulnerabilities. A number with **?** means the version is unknown
  but advisories exist for some versions.
- **Graph**: the app, its library categories and the libraries. Vulnerable
  libraries have a red or orange border.
- **Licenses**: libraries grouped by license. Copyleft, weak copyleft and
  proprietary licenses are marked. Licenses come from ApkSpy's catalogue, so
  check the project page before relying on them.

Click a library for its Maven coordinates, where its version came from, its
packages and native libraries, and each vulnerability's id, severity, summary,
affected versions and link.

### Vulnerability data

ApkSpy ships a curated set of advisories for libraries Android apps commonly
bundle (Log4j, Gson, Jackson, SnakeYAML, fastjson, Guava, protobuf, OkHttp's
Okio, jsoup, Apache Commons, Bouncy Castle, XStream...). **Update vulnerability
data** asks [OSV.dev](https://osv.dev), which aggregates the GitHub Security
Advisories and NVD, about every library in the list that has Maven
coordinates (only the coordinates and versions are sent), then merges the
answers into `vulndb.json` in the config directory. That file extends the
built-in data from then on. The update runs the Python set under Settings >
Terminal & Scripts and needs network access; ApkSpy itself makes no network
requests. `vulndb.json` can also be replaced by hand. Its format
(`apkspy-vulndb-1`) lists advisories with OSV-style version ranges.

MCP clients get the same list, with vulnerabilities, from `dependencies`.
