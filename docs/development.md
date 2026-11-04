# Development

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

## Source layout

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
├── docs/                 user and developer documentation
└── README.md
```

## Custom title bar

On Windows the native title bar is replaced by one drawn with ImGui that contains the app icon (from `assets/favicon.ico`, see **Assets**), the File, View and Navigate menus, the window title and the minimize, maximize and close buttons. `WindowFrame` subclasses the window procedure so Windows still provides the native behavior: edge and corner resizing, drag to move, double-click to maximize, Aero Snap, drag-to-restore, the system menu (icon click, caption right-click, Alt+Space) and the Windows 11 snap layouts flyout on the maximize button. On other platforms the native frame is kept. The close button, Alt+F4 and File > Exit all go through the same unsaved-changes confirmation.

## Assets

The solution folder can carry an `assets/` directory. At start-up the app looks for `assets/favicon.ico` (next to the executable, then one and two levels up - so both `build/` and Visual Studio's `x64/Debug` layouts find the solution folder - and finally the working directory). When found, the icon is decoded with the built-in `IcoLoader` (classic BMP frames at 1/4/8/24/32 bpp and PNG-compressed frames are supported) and used both as the OS window/taskbar icon and inside the custom title bar. Delete or replace `favicon.ico` and restart: a missing or undecodable asset simply keeps the defaults and is never fatal (a decode failure is reported in the Output panel).

## Memory

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

## Third-party code

Dear ImGui, GLFW, miniz, libwebp and stb are included in `include/` and `lib/`,
each under its own license. jadx, adb and Python are separate tools that you
install yourself.
