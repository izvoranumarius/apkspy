# ApkSpy

A dnSpy-style Android reverse-engineering workbench written in C++17 with
Dear ImGui. Projects hold one or more APKs; their contents are shown in a
dockable explorer, the code is decompiled with jadx, and sources, resources
and images can be viewed, searched and edited in tabs. On top of that:

- **Bytecode analysis** of every `classes*.dex` without jadx: smali
  disassembly, cross-references, call graphs, control-flow graphs, class
  hierarchy, string / URL / secret extraction, constant-argument data flow.
- **Native libraries**: ELF sections, segments, imports/exports, JNI entry
  points, demangled symbols, hex view, and for arm64-v8a libraries an
  AArch64 disassembler with function discovery, named calls (imports as
  `name@plt`), resolved string literals, callers and code-referenced strings.
- **Bookmarks and comments** on file lines and native addresses, saved in
  the project and shared with AI assistants over MCP.
- **Graphs** in the style of IDA, Ghidra and Cutter: interactive control-flow
  graphs for bytecode and arm64 functions, and call graphs for both.
- **Python scripting**: every MCP tool as a function of an `apkspy` module.
- **APK version comparison**: archive entries, permissions, classes and
  changed method bodies.
- **Live device tooling** over adb: devices, processes, Logcat, CPU / memory /
  thread monitor, and a JDWP **debugger** (threads, call stacks, locals with
  expandable objects and arrays, line and exception breakpoints, stepping).
- **MCP server** so AI assistants (Claude Code, Claude Desktop, any MCP
  client) can explore the open project and the live debugger - over HTTP
  from the running app, or headless over stdio.

## Layout

```
ApkSpy/
├── src/                  application code: headers (.hpp) live next to their sources
│   ├── app/              Application, Theme, WindowFrame, main, HeadlessMcp (--mcp mode)
│   ├── analysis/         DexFile, Dalvik (disassembler), ApkAnalysis (xrefs, CFG, call
│   │                     graph, strings), ElfFile, Arm64 (A64 decoder), NativeCode
│   │                     (functions, native xrefs), ApkDiff, AnalysisService (background jobs)
│   ├── debug/            Adb (shell-free adb wrappers), Jdwp (debug wire protocol client),
│   │                     DeviceService (devices, Logcat, monitor, DebugSession)
│   ├── mcp/              Json, McpServer (JSON-RPC + owner-thread dispatch), McpTools,
│   │                     McpTransports (stdio, loopback HTTP), McpHost
│   ├── core/             TreeNode, ContentSource, ApkArchive, JadxRunner, SearchService,
│   │                     Settings, Project, Workspace + small shared headers
│   │                     (TextUtils, LogSeverity, Paths, RootKind)
│   ├── document/         Document, SyntaxHighlighter
│   ├── image/            ImageDecoder, Texture
│   └── ui/               Panel, TitleBar, Explorer, Editor, Output, Search, Overview,
│       │                 Analysis, Devices / Debugger / Logcat, McpSettings,
│       │                 ImageViewer, FileBrowser, SettingsDialog, ShellIcons
├── include/              external dependency HEADERS only, one folder per library
│   ├── imgui/            Dear ImGui 1.91.9 headers (+ backends/, pinned on purpose:
│   │                     the editor reaches into imgui_internal.h)
│   ├── glfw/             GLFW 3.4 headers (GLFW/) used by the MSVC build
│   ├── miniz/            miniz 3.0.2 headers
│   ├── libwebp/          libwebp 1.5.0 headers (the internal src/**/*.h are part of it)
│   └── stb/              stb_image (header-only)
├── tests/                headless tests (core logic, analysis/MCP/devices, ImGui regressions)
│                         + ApkSpyTests.vcxproj (Windows build of the portable suite)
├── lib/                  external dependency implementation files only
│   ├── imgui/            Dear ImGui .cpp sources (+ backends/)
│   ├── glfw/             Windows x64 static library (lib-vc2022/glfw3.lib)
│   ├── miniz/            miniz .c sources
│   └── libwebp/          libwebp .c sources (dec/dsp/utils)
├── build/                build output (ignored by version control)
├── Makefile              Linux and macOS build (+ `make test`)
├── ApkSpy.sln            Visual Studio 2022 solution
└── README.md
```

## Custom title bar

On Windows the native title bar is replaced by one drawn with ImGui that contains the app icon (from `assets/favicon.ico`, see **Assets**), the File and View menus, the window title and the minimize, maximize and close buttons. `WindowFrame` subclasses the window procedure so Windows still provides the native behavior: edge and corner resizing, drag to move, double-click to maximize, Aero Snap, drag-to-restore, the system menu (icon click, caption right-click, Alt+Space) and the Windows 11 snap layouts flyout on the maximize button. On other platforms the native frame is kept. The close button, Alt+F4 and File > Exit all go through the same unsaved-changes confirmation.

## Assets

The solution folder can carry an `assets/` directory. At start-up the app looks for `assets/favicon.ico` (next to the executable, then one and two levels up - so both `build/` and Visual Studio's `x64/Debug` layouts find the solution folder - and finally the working directory). When found, the icon is decoded with the built-in `IcoLoader` (classic BMP frames at 1/4/8/24/32 bpp and PNG-compressed frames are supported) and used both as the OS window/taskbar icon and inside the custom title bar. Delete or replace `favicon.ico` and restart: a missing or undecodable asset simply keeps the defaults and is never fatal (a decode failure is reported in the Output panel).

## Build

Windows: open `ApkSpy.sln` in Visual Studio 2022, select x64 and press F5. Nothing else needs to be installed.

Linux and macOS: install GLFW 3 and pkg-config (`libglfw3-dev` on Debian and Ubuntu, `brew install glfw` on macOS), then run `make`. The binary is `build/apkspy`. `make run` builds and starts it, `make clean` removes `build/`.

Headless tests (Linux/macOS, no GUI needed):

```
make test
```

This builds and runs three suites: `apkspy_core_test` (workspace, projects,
jadx runs incl. cancellation, output-directory ownership, AXML decoding,
search, settings, ICO decoding for `assets/favicon.ico`),
`apkspy_platform_test` (see below) and `imgui_editor_test` (pins the editor
caret overlay and stable tab ids against the bundled ImGui version).

`apkspy_platform_test` is portable and also part of the Visual Studio
solution (`ApkSpyTests` project, output `build/<Config>/apkspy_platform_test.exe`).
It builds DEX, ELF and APK inputs in memory and covers JSON, MCP JSON-RPC
handling (validation, batching, cancellation, owner-thread dispatch and
timeouts), DEX parsing, the Dalvik disassembler, xrefs / call graph / CFG /
constant-argument flow, string classification, thousands of mutated DEX and
ELF files (must not crash), the Document line storage, every MCP tool end to
end against a real Workspace, the HTTP transport's token and Origin checks,
the JDWP client against a fake JDWP peer and the adb / Logcat parsers.
`apkspy_platform_test --write-sample <dir>` writes the synthetic
`sample.apk` + `sample.apkspy` for manual testing.

## jadx configuration

The jadx executable path lives in **File > Settings > JADX** (Visual-Studio-style dialog with Environment / JADX / Text Editor pages, `Ctrl+,`). From there you can:

- enter the path or use **Browse...** to pick the jadx launcher (on Windows select `jadx.bat`, on Linux/macOS the `jadx` shell script),
- press **Test installation** to run `jadx --version` and see the result,
- add extra command line arguments (for example `--show-bad-code`).

jadx is executed directly (no shell), so file names in the path can never
inject commands. Preferences are stored in the per-user config directory
(`%APPDATA%\ApkSpy` on Windows, `~/.config/apkspy` on Linux,
`~/Library/Application Support/ApkSpy` on macOS) together with the dock
layout file `apkspy.ini`; existing files next to the executable are imported
on the first start.

## Projects

- **File > New Project** starts an empty project, **Open Project** (`Ctrl+O`)
  and **Recent Projects** reopen saved ones (`.apkspy` files).
- **Add APK(s) to Project...** (or drag & drop) adds any number of APKs; each
  becomes its own group. Same-named files are kept apart ("base", "base (2)")
  and never share decompiled results.
- **Save Project** (`Ctrl+S`) is the single save command: it writes edited
  files to disk and then the project file.
- APK entries whose file has been moved or deleted stay in the project (a
  note appears in the Output panel); fix the path or remove the entry.
- Right-click an APK root in the Explorer for **Remove from Project**.

### Where decompiled results live

Decompiled output is cached under the system temp directory
(`<temp>/apkspy/<apk-name>_<hash>`), keyed by the APK's path, size and
modification time. The location is always derived by ApkSpy itself - a
`.apkspy` file never influences it - and every cache directory carries a
marker file: only directories ApkSpy created are ever deleted, and results
are only reused without re-running jadx when a previous run finished
cleanly. Rebuilding an APK automatically invalidates its old results.

## Use

### Workspaces

The **View** menu switches between task-focused layouts of the panels (`Ctrl+1`
to `Ctrl+5`), and the title shows the current one:

| Workspace | Main tool | Alongside |
| --- | --- | --- |
| **Code** | Editor | Explorer, Overview, Search, Bookmarks, Output |
| **Analysis** | Analysis | Editor, Bookmarks |
| **Debug** | Debugger | Devices, Editor, Logcat |
| **Network** | Traffic | Logcat |
| **Scripts** | Script | Output |

The status bar shows the latest message and what is going on from any
workspace: decompiling, analysis, the debugger running or paused, traffic
capture, a script and the MCP server. Click it to show or hide the full log.

Panels keep their contents across workspaces, and each workspace remembers its
own arrangement: drag panels freely, add or remove them with **View > Panels in this
Workspace**, and restore one with **View > Reset Workspace Layout**. Navigation follows the work: attaching the debugger opens Debug, and
opening a file from a workspace without an editor switches to one that has it.

Actions live on the data, as in IDA and Ghidra. Double-click opens or follows,
right-click lists what else can be done, and tooltips show the keys.

### Graphs

Control-flow graphs show a function's basic blocks: green is the taken branch,
red the fall-through, blue an unconditional jump and dashed orange an exception
handler; exit blocks have a red border. Call graphs show a function with its
callers on the left and callees on the right. Open them from **Analysis**:
right-click a method in Classes (`Space` on a hovered method opens its CFG), or
use **Graph** and **Calls** in Native (`Space` toggles the listing and the
graph). The function list hides to give the graph the width; **Show list**
brings it back.

Drag to pan, use the wheel to zoom around the cursor, `F` fits the graph, and
the minimap jumps around large ones. Click a block to highlight its edges.
Double-click a block to open its listing, a call or jump inside a native block
to follow it, or a function in a call graph to recentre on it. Branch tables
(`br` on a computed address) end a block: their targets are only known at run
time. Comments and bookmarks show in native graphs, where `;` and `Ctrl+B` work
on the line you clicked.

### Scripting

The **Scripts** workspace edits and runs Python scripts (`F5`) against the open
project, with output in the Output panel below the editor (filter it to
`[scripts]` to see only that). Each MCP tool is a function of the
`apkspy` module, with the tool's arguments and structured results:

```python
import apkspy

apkspy.run_analysis()
for c in apkspy.list_classes(filter="login")["classes"]:
    print(c)

# Open a function's graph for yourself, then leave a comment on it.
apkspy.show_native(path="lib/arm64-v8a/libfoo.so", target="Java_com_foo_check", view="graph")
apkspy.add_annotation(kind="comment", path="lib/arm64-v8a/libfoo.so", address="0x1234", text="license check")
```

`apkspy.tools()` lists every tool, failures raise `apkspy.ApkSpyError`, and a
trailing underscore passes a Python keyword (`get_class(class_="com.a.B")`).
Scripts save as you type and use your installed Python, so any of its packages
work; set its path under File > Settings > Scripts when `python` is not on `PATH`. They run with your user's full
rights, so only run scripts you trust. Files live in the `scripts` folder of
the ApkSpy config directory. ApkSpy reaches them through a private local
endpoint with a fresh token, whatever the MCP server setting.

### Explorer

- **Files** - the original archive contents straight from the APK.
- **Decompiled** - the jadx output. While jadx is running an indeterminate
  progress bar, the elapsed time, the warning/error counters and a **Cancel**
  button are shown, and the tree grows live as results are written. When the
  decompilation finishes the UI switches to this tab automatically.
- Single-click a file to open it in a **preview tab**; clicking another file replaces the preview.
- Double-click a file (or use *Open in New Tab*) to open a **permanent tab** that stays open.
- Double-clicking a preview tab promotes it to a permanent tab.
- Right-click any item for **Open**, **Open in New Tab** and **Copy Path**; APK roots also offer **Remove from Project**.
- Right-click files for **Export Raw...** / **Export Decoded...** (compiled Android XML becomes readable XML) and folders for **Export Folder (raw/decoded)...**; the export progress and a Cancel button appear at the bottom of the panel. Names coming from archive content are sanitised (zip-slip safe).
- Click selects a row, Ctrl+click toggles rows, Shift+click and click-drag
  select a range; Ctrl+C copies the selected names. Rows are
  virtualized, so packages with thousands of classes stay smooth.

### Editor tabs

- Preview tabs are labelled `(preview)`; modified files carry a `*` marker.
- Files open in a fast **read-only view**; the **Edit** toggle above the
  document switches to the in-place editor, which keeps the syntax colours
  while typing (`Ctrl+S` saves through the project). APK entries from the
  archive are always read-only.
- Close tabs with the `X` button, middle click, or the tab context menu (**Close**, **Close All**, **Close Others**). Closing a modified tab asks for confirmation (Save / Don't Save / Cancel).
- Binary XML entries inside an APK (`AndroidManifest.xml`, `res/**/*.xml`) are decoded to readable XML (values include strings, ints, references, colors and dimensions like `-4dp`).
- The **Export...** toolbar button saves the active document (the edit buffer when it has unsaved edits).
- **Ctrl+click a class** to open the file that declares it (identifier underlining while Ctrl is held); same-package classes win over same-named classes in other packages.
- **Back/Forward navigation** (`Alt+Left` / `Alt+Right`, mouse buttons 4/5 or the `‹ ›` toolbar buttons) undo and redo jumps: search hits, explorer jumps, Go to Line. Closed tabs re-open on demand; removed APKs are skipped.
- **Find in file** (`Ctrl+F`) opens a slim bar above the document with match-case and whole-word toggles, prev/next (`Enter`/`F3`, `Shift` for backward), a hit counter and per-tab state; matches are highlighted in both the viewer and the editor. **Go to Line** (`Ctrl+G`) jumps to a 1-based line number. Both are also in **View** menu.
- Open tabs and the panel layout are remembered between sessions; use **View > Reset Workspace Layout** to restore the current workspace's default layout.

### Overview

The **Overview** panel shows one APK at a time (selector when the project has several): app label, package, version, min/target SDK, `debuggable`/`allowBackup` badges, the declared permissions, all manifest components and the signing certificates (v1/v2/v3 with SHA-256 fingerprints and subject/issuer). Clicking a component jumps to its class in the decompiled sources; if the class is not there (framework code), the manifest opens instead.

### Search

The Search panel covers the decompiled output with five modes: **Full text**, **Filenames**, **Classes**, **Methods** and **Fields**. Single-click a hit to preview it, double-click to keep it open; the file opens **at the matching line** (the line is highlighted). With several APKs in the project a selector picks which one to search; a search is suspended while that APK is still being decompiled. Hit excerpts are capped in length, the result list at 3000 hits, and files above 4 MB are skipped (both are reported in the panel).

### Output

Progress, warnings (yellow) and errors (red) from jadx and ApkSpy itself, with a severity filter and Clear. Lines are selectable (click, Shift+click, drag, Ctrl+A) and copy with Ctrl+C or the context menu. jadx runs that finish with errors for some classes keep everything else (jadx exits non-zero as soon as any class fails). The severity classification is shared with the warning/error counters, and auto-scroll only engages while you are already at the bottom.

Supported source highlighting: Java, Kotlin, XML, JSON, smali, Groovy/Gradle, YAML, HTML, JavaScript and CSS. Supported images: JPEG, PNG, GIF, BMP, TGA, PSD, HDR, PNM and WebP (first frame of animated files; image dimensions are bounds-checked before decoding). Fonts cover Latin, Greek, Cyrillic and common CJK characters and scale with the monitor DPI.

### Analysis (bytecode)

Opening the **Analysis** workspace parses every `classesN.dex` on a background
thread with progress and Cancel. The
analysis needs no jadx and works on obfuscated or partially broken APKs
(every offset is bounds-checked; malformed structures are skipped).

- **Classes** - every class (filterable, virtualized), its methods with
  size, and per-method **Smali**, **Callers**, **Callees** and **CFG**
  actions. Double-click a class or method to open its smali disassembly as
  a read-only tab (find, go to line and Back/Forward work as for any file).
  The class context menu offers the decompiled source, type references and
  the class hierarchy.
- **Xrefs** - results of the last query (callers, callees, string or type
  uses); click a row to jump to the exact instruction.
- **Strings** - the DEX string tables with heuristics for URLs, IP
  addresses, API paths, secrets / tokens and e-mail addresses; click a
  string to list the code using it.
- **Graph** - the control-flow graph of a method: basic blocks with their
  instructions, green = branch taken, red = fall-through, blue = jump,
  dashed orange = exception handler. Drag with the right / middle mouse
  button to pan, double-click a block to open the listing there, **Copy
  DOT** exports Graphviz.
- **Native** - `lib/<abi>/*.so`: ELF class / machine / SONAME / NEEDED,
  JNI entry points, exports and imports (demangled), sections and segments,
  and the hex view. For arm64-v8a libraries two more views:
  - **Functions** - every function (symbols, PLT import stubs named
    `name@plt`, and call targets without a symbol as `sub_<addr>`) with its
    AArch64 disassembly. Calls and jumps are named, `adrp` + `add` / `ldr`
    pairs are resolved to the string literal, GOT slot or symbol they
    address, local branch targets are highlighted, and the callers of the
    function are listed. Double-click a call or jump to follow it,
    Backspace / **<** goes back, and right-click offers **Open listing in
    editor**. Double-click a JNI / export symbol to disassemble it.
  - **Strings** - the string literals the code actually references, each
    with the function that uses it (more precise than scanning `.rodata`).

  The function list and reference index are built once per library on a
  worker (cancellable) and shared with the MCP tools. The decoder covers the
  base A64 integer, load/store, branch, system and scalar FP instructions
  and the common Advanced SIMD groups (more than 99.6 % of the
  instructions in Android's libc, libz and libblas); anything else prints
  as `.inst 0x...`. 32-bit ARM and x86 libraries keep the ELF views.
- **Compare** - pick a second APK of the project: changed / added / removed
  archive entries, permission changes and - when both APKs are analysed -
  added / removed classes and changed method bodies (compared on a
  normalised disassembly, so index renumbering between builds is ignored).

The analysis of an APK is freed when it is removed from the project or the
project is closed.

### Resources

`resources.arsc` is parsed when first needed: decoded binary XML (manifest,
layouts) shows `@string/app_name` instead of `@ref/0x7F0E0023`, the Overview
shows the real app label, and **Analysis > Resources** lists every resource
(id, type, name, default value, number of configurations) with a type filter
and search. Right-click a resource for its id / reference, or (after the
bytecode analysis) **Find code using this id**, which lists the methods that
pass the id to a call.

### Traffic sniffer

**Start capture** runs a local proxy (127.0.0.1 only) and routes the device
through it (`adb reverse` + the device's global HTTP proxy setting); **Stop
capture** undoes both. Plain HTTP requests are captured with headers and bodies
(chunked / gzip decoded, JSON pretty-printed, copy as cURL); HTTPS connections
appear with host, TLS server name, timing and sizes, and their contents stay
encrypted. The **Endpoints** view groups requests into an API map
(`/users/{id}`) and marks endpoints whose host or path also appears in the
app's code. The **...** menu has **Reset device proxy** for a device left routed
after a crash. The port is under File > Settings > Android.

### Zoom and layout

**View > Zoom In / Out / Reset** (`Ctrl+=`, `Ctrl+-`, `Ctrl+0`, or
`Ctrl` + mouse wheel) scales all text and the UI, including the title bar;
the zoom is remembered. Panels lay their controls out to the available width
(rows wrap instead of being cut off at the dock splitter), and long names
show in full as tooltips.

### Bookmarks and comments

Annotate what you find, IDA-style, in the viewer of any file of the APK or
decompiled trees and in the native listing:

- Click a line or instruction, then **Ctrl+B** toggles a bookmark and **;**
  adds or edits a comment; right-click has the same actions.
- Bookmarks show an orange dot in the gutter (an orange address in native
  listings); comments appear at the end of the line, with the full text on hover.
- The **Bookmarks** panel lists everything with a kind and text filter.
  Double-click jumps there, right-click edits, copies or deletes.

Annotations are saved in the `.apkspy` project file, so **Save Project** keeps
them and the title shows `*` until then. They belong to the APK they were made
on and are removed with it. A line annotation stays on its line number, so it
does not follow edits made to the file. Generated listings (smali, native
listings opened in the editor) are recreated on demand and cannot be annotated.

### Hex viewer

Binary files (DEX, native libraries, anything that is not text or an image)
open in the hex viewer: jump to an offset, search hex patterns
(`64 65 78 0a`) or text with wrap-around, click a byte to select it, and the
**data inspector** shows the value at the selection as signed / unsigned 8-,
16-, 32- and 64-bit integers, float, double, ULEB128 and ASCII.

### Devices, Logcat and Debugger

These panels use adb from the Android platform-tools (**File > Settings >
Android / ADB** sets the path; the default `adb` is looked up on PATH).

- **Devices** - connected devices and emulators, their processes (debuggable
  ones in green, kernel threads hidden unless asked for). Double-click a
  process to attach the debugger and open the Debug workspace (or monitor it
  when it is not debuggable);
  right-click for Attach debugger, Monitor, Show in Logcat (filters the log
  to that pid) and copy name / pid. The monitor samples CPU (share of the device), RSS and thread count once per
  second.
- **Logcat** - live device log with level, pid, tag and text filters, pause
  and auto-scroll. The log is a bounded ring buffer (50 000 lines), so a
  chatty device cannot exhaust memory.
- **Debugger** - attaches to a debuggable app through JDWP
  (`adb forward tcp:N jdwp:<pid>`): threads, call stack (with source lines
  when the app has debug info), local variables of the selected frame,
  breakpoints on `class.method` or `class.method:line` (classes that are not
  loaded yet are armed on load), suspend / resume and step into / over /
  out. Objects and arrays in **Locals** expand into their instance fields
  (along the class chain, labelled with the declaring class) or first 200
  elements, loaded on first open, with cycle detection. **Add...**
  adds an exception breakpoint for the class typed in the class field (and
  its subclasses) or for any exception, on caught and / or uncaught throws;
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

### MCP server (AI integration)

ApkSpy exposes the open project to AI assistants through the
[Model Context Protocol](https://modelcontextprotocol.io). Two ways to run it:

**From the running app** - open **File > Settings > AI (MCP)** and press
**Start**. The endpoint listens on
`http://127.0.0.1:<port>/mcp` (loopback only, default port 8765) and by
default requires a bearer token; the page's buttons copy ready-to-paste client
configuration, e.g. for Claude Code:

```
claude mcp add --transport http apkspy http://127.0.0.1:8765/mcp --header "Authorization: Bearer <token>"
```

In this mode the assistant sees exactly what you see and can open files in
your editor (`open_in_editor`).

**Headless (stdio)** - the client launches ApkSpy itself, no window:

```
ApkSpy --mcp --project path/to/project.apkspy
ApkSpy --mcp --apk app.apk [--apk other.apk] [--analyze] [--no-decompile] [--no-devices]
```

**Tools** (all with JSON-schema validated input and structured output):
`list_apks`, `apk_info` (package, versions, SDKs, flags, permissions,
components, signatures), `get_manifest`, `list_files`, `read_file`,
`hexdump`, `search_code`, `decompile_class`, `run_analysis` (long-running,
progress + cancellation), `dex_info`, `list_classes`, `get_class`,
`get_method` (smali, callees, constant arguments), `xrefs`, `call_graph`,
`control_flow_graph` (JSON or DOT), `class_hierarchy`, `search_strings`,
`find_endpoints`, `list_resources`, `resolve_resource`, `list_native_libs`,
`inspect_native_lib`, `native_functions`, `disassemble_native`,
`native_xrefs`, `native_strings`, `compare_apks`, the GUI-only
`open_in_editor`, `show_native` and `show_panel`, the device tools
`device_list`, `device_info`, `device_processes`, `logcat_read`,
`process_stats`, `process_threads`, `process_backtrace`, `debugger_state`,
`debugger_attach`, `debugger_control`, `debugger_select`,
`debugger_breakpoint` (line and exception breakpoints),
`debugger_inspect` (object fields / array elements), the traffic tools
`traffic_status`, `traffic_control`, `traffic_list`, `traffic_get`,
`traffic_endpoints`, and `list_annotations`, `add_annotation`,
`remove_annotation`, plus `native_cfg` and the GUI-only `show_method`. That is
54 tools in total, 50 headless. The headless server saves
annotation changes to the project file on exit; started without a project
file, it has nowhere to keep them.

Design and safety:

- Tool handlers run on the thread that owns the project (the UI thread, or
  the main loop in headless mode), one at a time - concurrent requests can
  never observe or corrupt half-updated state. Expensive work (searching,
  analysis queries, adb calls) runs afterwards on the request's own thread
  using immutable snapshots, so the UI never stalls.
- Long-running calls honour `notifications/cancelled`, report progress over
  stdio, and are cancelled when the server stops.
- Files are only reachable through the project trees (no raw filesystem
  paths); there is no tool that executes arbitrary commands. Results are
  size-capped and paginated (`offset` / `limit`).
- The HTTP endpoint binds 127.0.0.1 only, rejects requests whose `Origin`
  is not local (DNS-rebinding protection) and compares the bearer token in
  constant time.

### Memory

Code documents keep their text in one buffer with 4-byte line offsets (no
`std::string` per line); file reads are single sized reads; zip entries are
inflated straight into their final buffer (declared sizes are capped before
anything is allocated); the symbol index stores each path once; the font
atlas frees its CPU-side pixel and TTF copies after the GPU upload and bakes
the common CJK subsets by default (**Settings > Environment > Full CJK glyph
coverage** restores all 21k ideographs at roughly +190 MB); Logcat and the
monitor use bounded ring buffers. MSVC Debug builds still cost more than
Release per allocation (checked iterators, debug heap), but no longer by a
factor that grows with the size of open files.
