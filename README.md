# ApkSpy

A dnSpy-style APK inspector written in C++17 with Dear ImGui. Projects hold
one or more APKs; their contents are shown in a dockable explorer, the code
is decompiled with jadx, and sources, resources and images can be viewed,
searched and edited in tabs.

## Layout

```
ApkSpy/
├── src/                  application code: headers (.hpp) live next to their sources
│   ├── app/              Application, Theme, WindowFrame, main
│   ├── core/             TreeNode, ContentSource, ApkArchive, JadxRunner, SearchService,
│   │                     Settings, Project, Workspace + small shared headers
│   │                     (TextUtils, LogSeverity, Paths, RootKind)
│   ├── document/         Document, SyntaxHighlighter
│   ├── image/            ImageDecoder, Texture
│   └── ui/               Panel, TitleBar, Explorer, Editor, Output, Search panels,
│       │                 ImageViewer, FileBrowser, SettingsDialog, ShellIcons
├── include/              external dependency HEADERS only, one folder per library
│   ├── imgui/            Dear ImGui 1.91.9 headers (+ backends/, pinned on purpose:
│   │                     the editor reaches into imgui_internal.h)
│   ├── glfw/             GLFW 3.4 headers (GLFW/) used by the MSVC build
│   ├── miniz/            miniz 3.0.2 headers
│   ├── libwebp/          libwebp 1.5.0 headers (the internal src/**/*.h are part of it)
│   └── stb/              stb_image (header-only)
├── tests/                headless tests (core logic + ImGui regressions)
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

This builds and runs two suites: `apkspy_core_test` (workspace, projects,
jadx runs incl. cancellation, output-directory ownership, AXML decoding,
search, settings, ICO decoding for `assets/favicon.ico`) and
`imgui_editor_test` (pins the editor caret overlay and stable tab ids
against the bundled ImGui version).

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
- Click-and-drag selects rows; Ctrl+C copies the selected names. Rows are
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
- Open tabs and the panel layout are remembered between sessions; use **View > Reset Layout** to restore the default docking layout.

### Overview

The **Overview** panel shows one APK at a time (selector when the project has several): app label, package, version, min/target SDK, `debuggable`/`allowBackup` badges, the declared permissions, all manifest components and the signing certificates (v1/v2/v3 with SHA-256 fingerprints and subject/issuer). Clicking a component jumps to its class in the decompiled sources; if the class is not there (framework code), the manifest opens instead.

### Search

The Search panel covers the decompiled output with five modes: **Full text**, **Filenames**, **Classes**, **Methods** and **Fields**. Single-click a hit to preview it, double-click to keep it open; the file opens **at the matching line** (the line is highlighted). With several APKs in the project a selector picks which one to search; a search is suspended while that APK is still being decompiled. Hit excerpts are capped in length, the result list at 3000 hits, and files above 4 MB are skipped (both are reported in the panel).

### Output

Progress, warnings (yellow) and errors (red) from jadx and ApkSpy itself, with a severity filter and Clear. The severity classification is shared with the warning/error counters, and auto-scroll only engages while you are already at the bottom.

Supported source highlighting: Java, Kotlin, XML, JSON, smali, Groovy/Gradle, YAML, HTML, JavaScript and CSS. Supported images: JPEG, PNG, GIF, BMP, TGA, PSD, HDR, PNM and WebP (first frame of animated files; image dimensions are bounds-checked before decoding). Fonts cover Latin, Greek, Cyrillic and common CJK characters and scale with the monitor DPI.
