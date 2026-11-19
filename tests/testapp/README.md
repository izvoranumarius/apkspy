# ApkSpy HTTPS test app

A minimal Android app to verify the whole HTTPS interception workflow end to
end against a real device or emulator. It is intentionally tiny: one screen
with buttons that fire plain HTTP, HTTPS, HTTPS-with-pinning-style checks,
gzip and WebSocket requests at `https://origin.test` (or any host you set),
and shows the responses - so you can see in ApkSpy's Requests tab exactly what
was captured, and what each transport does.

## Build & install

```
# from tests/testapp/ (Android Studio, or on the command line):
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Command line builds need the Android SDK (platform 34, build-tools) and
Gradle; from Android Studio just press Run. The app is debuggable, so its
`debug-overrides` network security config (see below) trusts user-installed
CAs on debug builds - which is exactly the configuration to test.

## What to check in ApkSpy

1. **File > Settings > Network**: HTTPS interception on (default), then
   **Traffic panel > Start capture**.
2. **HTTPS & certificates** in the Traffic panel: install the CA for the
   *user* (Settings opens on the device), then **Re-check** - the dialog
   should show the CA as installed.
3. In the app:
   - **HTTPS GET / POST** - the request and its JSON response must appear in
     ApkSpy's Requests tab with headers, cookies and bodies (not as a tunnel).
   - **GZIP** - the body shows decoded (the note says "decoded from gzip").
   - **WebSocket** - open the request in the list: the WebSocket tab shows
     every frame, direction and payload.
   - **Untrusting HTTPS** - this button calls the same host with a
     `network_security_config` that trusts only system CAs: ApkSpy records
     the failed handshake with the reason (unknown_ca / pinning-like), which
     is the diagnostic path for apps that refuse the proxy certificate.
   - **QUIC (Http3)** - if the host speaks HTTP/3 and the app has QUIC
     enabled, that traffic bypasses the TCP proxy (see the note in the
     HTTPS & certificates dialog about blocking UDP 443).
4. Rooted device / emulator with `adb root`: use **Install into the system
   store**, restart the app, and the *system-trust* variant (release-style
   config) becomes interceptable too.

The manifest's `usesCleartextTraffic="true"` and the debug-overrides are
deliberate: this is a test build for authorized traffic analysis, not a
template for production apps.
