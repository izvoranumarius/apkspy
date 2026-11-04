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
