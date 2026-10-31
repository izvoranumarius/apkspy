# ApkSpy

A dnSpy-style APK inspector written in C++17 with Dear ImGui. It opens an APK, shows its contents in a dockable explorer, decompiles the code with jadx, and lets you view, search and edit sources, resources and images in tabs.

## Layout

```
ApkSpy/
├── src/                  application code: headers (.hpp) live next to their sources
│   ├── app/              Application, Theme, WindowFrame, main
│   ├── core/             TreeNode, ContentSource, ApkArchive, JadxRunner, SearchService,
│   │                     Settings, Workspace
│   ├── document/         Document, SyntaxHighlighter
│   ├── image/            ImageDecoder, Texture
│   └── ui/               Panel, TitleBar, Explorer, Editor, Output, Search panels,
│       │                 ImageViewer, FileBrowser, SettingsDialog
├── include/              external dependency HEADERS only, one folder per library
│   ├── imgui/            Dear ImGui 1.91.9 headers (+ backends/)
│   ├── glfw/             GLFW 3.4 headers (GLFW/) used by the MSVC build
│   ├── miniz/            miniz 3.0.2 headers
│   ├── libwebp/          libwebp 1.5.0 headers (kept under src/ as the library expects)
│   └── stb/              stb_image (header-only)
├── tests/                headless smoke test for the core logic
├── lib/                  external dependency implementation files only, one folder per library
│   ├── imgui/            Dear ImGui .cpp sources (+ backends/)
│   ├── glfw/             Windows x64 static library (lib-vc2022/glfw3.lib)
│   ├── miniz/            miniz .c sources
│   └── libwebp/          libwebp .c sources (dec/dsp/utils)
├── build/                build output (ignored by version control)
├── Makefile              Linux and macOS build
├── ApkSpy.sln            Visual Studio 2022 solution
└── README.md
```

## Custom title bar

On Windows the native title bar is replaced by one drawn with ImGui that contains the app icon, the File, View and Tools menus, the window title and the minimize, maximize and close buttons. `WindowFrame` subclasses the window procedure so Windows still provides the native behavior: edge and corner resizing, drag to move, double-click to maximize, Aero Snap, drag-to-restore, the system menu (icon click, caption right-click, Alt+Space) and the Windows 11 snap layouts flyout on the maximize button. On other platforms the native frame is kept.

## Build

Windows: open `ApkSpy.sln` in Visual Studio 2022, select x64 and press F5. Nothing else needs to be installed.

Linux and macOS: install GLFW 3 and pkg-config (`libglfw3-dev` on Debian and Ubuntu, `brew install glfw` on macOS), then run `make`. The binary is `build/apkspy`. `make run` builds and starts it, `make clean` removes `build/`.

Headless smoke test (Linux/macOS, verifies the core logic without a GUI):

```
g++ -std=c++17 -O1 -Isrc -Iinclude -Iinclude/imgui -Iinclude/miniz \
    tests/apkspy_core_test.cpp \
    src/core/*.cpp src/document/*.cpp \
    lib/miniz/miniz.c lib/miniz/miniz_tinfl.c lib/miniz/miniz_tdef.c lib/miniz/miniz_zip.c \
    -o /tmp/apkspy_test -lpthread && /tmp/apkspy_test
```

## jadx configuration

The jadx executable path lives in **Tools > Settings > JADX** (Visual-Studio-style dialog with Environment / JADX / Text Editor pages, `Ctrl+,`). From there you can:

- enter the path or use **Browse...** to pick the jadx launcher (on Windows select `jadx.bat`, on Linux/macOS the `jadx` shell script),
- press **Test installation** to run `jadx --version` and see the result,
- add extra command line arguments (for example `--show-bad-code`).

The path, the arguments and every other preference are saved to `apkspy.settings` next to the dock layout file `apkspy.ini` and restored on the next start.

## Use

Drag an APK onto the window or press Ctrl+O. The **Open APK** dialog is focused on a single task: picking an APK file (type the path or use Browse, with live file-size feedback).

The **Explorer** window has two tabs:

- **Files** - the original archive contents straight from the APK.
- **Decompiled** - the jadx output. While jadx is running an indeterminate progress
  bar, the elapsed time, and the warning/error counters are shown, and the tree grows
  live as results are written, so partially generated files can be opened right away.
  When the decompilation finishes the UI switches to this tab automatically.

Progress, warnings (yellow) and errors (red) are also shown in the **Output** panel, which can filter by severity and be cleared.

### Explorer

- Single-click a file to open it in a **preview tab**; clicking another file replaces the preview.
- Double-click a file (or use *Open in New Tab*) to open a **permanent tab** that stays open.
- Double-clicking a preview tab promotes it to a permanent tab.
- Right-click any item for **Open**, **Open in New Tab** and **Copy Path**.

### Editor tabs

- Preview tabs are labelled `(preview)`; modified files carry a `*` marker. Files
  on disk are editable immediately and saved with `Ctrl+S`, and keep their syntax
  colours while typing. Binary XML entries inside an APK
  (`AndroidManifest.xml`, `res/**/*.xml`) are decoded to readable XML.
- Close tabs with the `X` button, middle click, or the tab context menu (**Close**, **Close All**, **Close Others**, **Reopen Closed Tab**).
- Closing a modified tab asks for confirmation (Save / Don't Save / Cancel). Decompiled files can be edited in place (`Ctrl+S` to save); APK entries are shown read-only.
- Closed tabs can be restored with `Ctrl+Shift+T`.
- Open tabs and the panel layout are remembered between sessions; use **View > Reset Layout** to restore the default docking layout.

### Search

The Search panel covers the decompiled output with five modes: **Full text**, **Filenames**, **Classes**, **Methods** and **Fields**. Single-click a hit to preview it, double-click to keep it open; the file opens at the matching line.

Supported source highlighting: Java, Kotlin, XML, JSON, smali, Groovy/Gradle, YAML, HTML, JavaScript and CSS. Supported images: JPEG, PNG, GIF, BMP, TGA, PSD, HDR, PNM and WebP. Animated formats show their first frame.
