# Getting started

## Install

Download the Windows build from the
[Releases page](https://github.com/izvoranumarius/apkspy/releases), unzip it
anywhere and run `ApkSpy.exe`. To build it yourself, see
[Development](development.md).

ApkSpy opens APKs on its own. These optional tools unlock the rest:

| Tool | Used for | Set its path in |
| --- | --- | --- |
| [jadx](https://github.com/skylot/jadx) | Decompiled Java sources | File > Settings > JADX |
| adb (Android platform-tools) | Devices, Logcat, debugger, traffic | File > Settings > Android / ADB |
| Python 3 | Scripts | File > Settings > Scripts |

## Set up jadx

The jadx path lives in **File > Settings > JADX** (`Ctrl+,`). From there you can:

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

## Where decompiled results live

Decompiled output is cached under the system temp directory
(`<temp>/apkspy/<apk-name>_<hash>`), keyed by the APK's path, size and
modification time. The location is always derived by ApkSpy itself - a
`.apkspy` file never influences it - and every cache directory carries a
marker file: only directories ApkSpy created are ever deleted, and results
are only reused without re-running jadx when a previous run finished
cleanly. Rebuilding an APK automatically invalidates its old results.

## Workspaces

The button at the bottom left of the status bar (or the **View** menu) switches between task-focused layouts of the panels (`Ctrl+1`
to `Ctrl+5`), and the title shows the current one:

| Workspace | Main tool | Alongside |
| --- | --- | --- |
| **Code** | Editor | Explorer, Search (find in project, Ctrl+Shift+F) and Overview as sidebar tabs; Bookmarks, Output, Terminal |
| **Analysis** | Analysis | Function, Decompiler, Editor, References, Bookmarks |
| **Debug** | Debugger | Devices, Editor, Logcat, Terminal |
| **Network** | Traffic | Logcat, Terminal |
| **Scripts** | Script | Output, Terminal |

The status bar shows the latest message and what is going on from any
workspace: decompiling, analysis, the debugger running or paused, traffic
capture, a script and the MCP server. Click it to show or hide the full log.

Panels keep their contents across workspaces, and each workspace remembers its
own arrangement: drag panels freely, add or remove them with **View > Panels in this
Workspace**, and restore one with **View > Reset Workspace Layout**. Navigation follows the work: attaching the debugger opens Debug, and
opening a file from a workspace without an editor switches to one that has it.

Actions live on the data, as in IDA and Ghidra. Double-click opens or follows,
right-click lists what else can be done, and tooltips show the keys.

## Getting around

- **Quick open** (`Ctrl+P`) finds any file of every APK and its decompiled
  sources from a few letters of its name, in order.
  The same box runs commands after `>` (`Ctrl+Shift+P`), finds classes of the
  analysed APKs after `@`, and goes to a line after `:`, like VS Code, Binary
  Ninja and IDA's Jump Anywhere.
- **Breadcrumbs** above a file show its folders; click one to show it in the
  Explorer. Right-click a tab for **Reveal in Explorer**, **Copy Path**, **Keep
  Open** (for a preview tab) and **Close to the Right**.
- **Terminal** (`` Ctrl+` ``): a real shell (PowerShell on Windows, your login
  shell elsewhere) started in the project folder, with the configured adb and
  jadx first on `PATH`. Drag to select; `Ctrl+C` copies a selection and
  interrupts otherwise; `Ctrl+V` pastes. The shell is set under
  **File > Settings > Scripts**. Windows needs version 10 1809 or later.
- With nothing open, the editor shows a **welcome page** with recent projects
  and these shortcuts.

## Keyboard shortcuts

| Keys | Action |
| --- | --- |
| `Ctrl+P` | Go to a file (`>` commands, `@` classes, `:` line) |
| `Ctrl+Shift+P` | Run a command |
| `` Ctrl+` `` | Show or hide the terminal |
| `Ctrl+1` to `Ctrl+5` | Switch workspace |
| `Ctrl+O` / `Ctrl+S` | Open / save project |
| `Ctrl+,` | Settings |
| `Ctrl+F` / `F3` / `Ctrl+G` | Find in file / next match / go to line |
| `Alt+Left` / `Alt+Right` | Back / forward |
| `Ctrl+B` / `;` | Bookmark / comment |
| `Space` / `X` | On a method: control-flow graph / callers |
| `F5` | Run script |
| `F9` / `F12` | Debugger: resume / pause |
| `F7` / `F8` / `Shift+F8` | Debugger: step into / over / out |
| `Ctrl+=` / `Ctrl+-` / `Ctrl+0` | Zoom in / out / reset |

## Zoom and layout

**View > Zoom In / Out / Reset** (`Ctrl+=`, `Ctrl+-`, `Ctrl+0`, or
`Ctrl` + mouse wheel) scales all text and the UI, including the title bar;
the zoom is remembered. Panels lay their controls out to the available width
(rows wrap instead of being cut off at the dock splitter), and long names
show in full as tooltips.
