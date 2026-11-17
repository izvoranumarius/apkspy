# Debugging and network

## Devices, Logcat and Debugger

These panels use adb from the Android platform-tools (**File > Settings >
Android / ADB** sets the path; the default `adb` is looked up on PATH).

- **Devices** - connected devices and emulators, their processes (debuggable
  ones in green, kernel threads hidden unless asked for). Double-click a
  process to attach the debugger and open the Debug workspace (or monitor it
  when it is not debuggable);
  right-click for Attach debugger, Monitor, Show in Logcat (filters the log
  to that pid) and copy name / pid. The monitor samples CPU (share of the device), RSS and thread count once per
  second.
- **Logcat** - live device log with a level filter, one filter box
  (`text tag:Name pid:1234`), pause and auto-scroll. Attaching the debugger
  starts it, filtered to that process. The log is a bounded ring buffer (50 000 lines), so a
  chatty device cannot exhaust memory.
- **Debugger** - attaches to a debuggable app through JDWP
  (`adb forward tcp:N jdwp:<pid>`): threads, call stack (with source lines
  when the app has debug info), local variables of the selected frame,
  breakpoints on `class.method` or `class.method:line` (classes that are not
  loaded yet are armed on load), suspend / resume and step into / over /
  out. Objects and arrays in **Locals** expand into their instance fields
  (along the class chain, labelled with the declaring class) or first 200
  elements, loaded on first open, with cycle detection. **Add...**
  adds line breakpoints and exception breakpoints, for a class (and its
  subclasses) or for any exception, on caught and / or uncaught throws;
  the stop shows where it was thrown and caught, and the thrown object
  appears as `$exception` in Locals. When the program stops, the editor opens
  the code there: the smali listing on the exact instruction once the APK is
  analysed, or the decompiled class by line number otherwise. Shortcuts follow x64dbg: **F9** resume, **F12** pause, **F7** step
  into, **F8** step over, **Ctrl+F9** / **Shift+F8** step out. Detaching
  clears the breakpoints and resumes the app.

Debugging requires a debuggable app (`android:debuggable="true"`) and no
other debugger (Android Studio) attached to the same process. Since Android
14, ART refuses JDWP for non-debuggable apps even on userdebug and emulator
images, so to debug a release APK, rebuild it with the flag set. Every adb call is a fixed
argument template executed without a local shell; values that reach the
device shell (serials, package names, pids) are validated against strict
whitelists.

## Traffic capture

**Start capture** runs a local proxy (127.0.0.1 only) and routes the device
through it (`adb reverse` + the device's global HTTP proxy setting); **Stop
capture** undoes both. Plain HTTP requests are captured with headers and bodies
(chunked / gzip decoded, JSON pretty-printed, copy as cURL); HTTPS connections
appear with host, TLS server name, timing and sizes, and their contents stay
encrypted. The **Endpoints** view groups requests into an API map
(`/users/{id}`) and marks endpoints whose host or path also appears in the
app's code. The **...** menu has **Reset device proxy** for a device left routed
after a crash. The port is under File > Settings > Android.

### Request history

The **Requests** tab lists everything captured, as Burp's HTTP history does.

- **Filter**: by method, status class (2xx to 5xx, no answer), content type
  (JSON, HTML, XML, scripts / CSS, media / fonts, other); hide static files;
  show only edited requests, requests with parameters, or highlighted /
  commented ones; hide HTTPS connections. **Search inside bodies and headers
  too** makes the filter text also match decoded request and response bodies
  (it runs in the background). "Showing N of M" and **Clear filters** say when
  something is hidden.
- Click a column header to sort (again to reverse, a third time for arrival
  order). New requests are followed only while sorted by arrival.
- Right-click a request to **Highlight** it in a colour, **Add comment** (shown
  in the Note column and searchable), **Show only** or **Hide** its host, or send
  it to the Repeater or the Comparer.

### Match & replace

Rules that rewrite plain-HTTP traffic automatically as it passes through the
proxy, as in Burp. Each rule has a place (request first line, header or body;
response first line, header or body), a match, a replacement and an optional
comment; tick **Regex** for an ECMAScript regular expression (`$1`, `$2` in the
replacement). Rules apply top to bottom; the arrow moves one up.

- Header rules work line by line. An empty match adds the replacement as a new
  header; an empty replacement removes the matching headers.
- Body rules see the body decoded: chunked framing and gzip / deflate are undone
  when a rule matches, and Content-Length is set to the new size. A body that no
  rule matches is passed on byte for byte.
- **Presets** has common rules (replace the User-Agent, drop the cache
  validators, ask for uncompressed responses, add a CORS header...).
- **Hits** counts the replacements each rule made since the rules last changed.
- Rewritten requests and responses are marked *(edited)* in the Requests list.
  Rules are saved with ApkSpy's settings. Rules run before the intercept, so a
  held message already shows their effect.

### Intercept

As in Burp's proxy intercept: press **Intercept is off** to turn it on, and
plain-HTTP requests from the device stop in ApkSpy before they reach the
server. Tick **Responses** to also stop the server's answers before the app
gets them, and type part of a URL to hold only matching traffic.

Waiting messages are listed oldest first (`->` requests, `<-` responses). The
selected one opens in an editor: change anything, then **Forward** (`Ctrl+F`)
to send it on, or **Drop** to discard it (a dropped request never reaches the
server; a dropped response leaves the app without an answer). Content-Length is
updated to match an edited body. **Forward all** releases everything, and so do
turning intercept off and stopping the capture. Edited requests show as
*(edited)* in the Requests list. HTTPS connections always pass through
untouched: their contents are encrypted.

### Comparer

Shows what differs between two requests, responses or any text, as in Burp.
Right-click a captured request and choose **Send request to Comparer** or **Send
response to Comparer**; the Repeater and the Decoder have **To Comparer** too,
and **Paste as item** adds the clipboard. The two newest items are compared
(pick others in **A** and **B**, or **Swap** them).

The two sides line up: changed lines are amber with the differing words
highlighted, removed lines red, added lines green opposite a gap. The arrows step
from one difference to the next. Bodies are compared decoded (chunked, gzip) and
JSON is indented first, so a changed field shows as one changed line.

### Repeater

As in Burp: right-click a request and choose **Send to Repeater** (or select it
and press `Ctrl+R`). Each request gets a numbered tab with the request in an
editor on the left and the response on the right. Edit anything (method, path,
headers, body) and press **Send** (`Ctrl+Enter` or `Ctrl+Space`).

- The target (host, port, **HTTPS**) sits above the editor; **From Host header**
  fills it from the request. Captured HTTPS connections open with a request to
  their host for you to fill in.
- Plain HTTP goes out over a socket exactly as typed. HTTPS goes through
  Windows' own HTTP stack (WinHTTP). Redirects are not followed and no cookies
  are kept, so every send stands alone.
- **Options**: update Content-Length to match the body (on by default), ignore
  certificate errors (for test servers with self-signed certificates), rename
  the tab.
- Every send is kept: the arrows step through the tab's history, request and
  response together.
- The response shows as **Raw**, **Pretty** (dechunked, decompressed, JSON
  indented) or **Headers**; **To Decoder** opens the body in the Decoder.

### Test emulator

Any device or emulator works. A barebones one (AOSP image, no Google apps):
install the Android SDK command-line tools, then the `emulator`,
`platform-tools`, `platforms;android-34` and
`system-images;android-34;default;x86_64` packages, create a device with
`avdmanager create avd`, and start it with `emulator -avd <name>`. On Windows
the emulator uses the Windows Hypervisor Platform when it is available.
