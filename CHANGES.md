# Changelog

## Decompiler

- **Decompiler** panel in the Analysis workspace, laid out as in Cutter:
  navigator | listing or graph over References | Decompiler (with jadx's Java
  as a tab behind it). ApkSpy's own engines decompile the selection without
  jadx or Ghidra: Dalvik methods to Java-like code, arm64 functions to C-like
  code, with `if` / `else`, `while`, `switch` and try / catch rebuilt.
- Lines and instructions stay linked both ways; double-click or Enter follows
  a call. As in IDA, **N** renames and **Y** retypes the variable under the
  cursor; names and types are saved with the project.
- MCP: `decompile_method`, `decompile_native` and `rename_variable`; renames
  from an AI assistant show up in the panel at once.
- **Find in project** (`Ctrl+Shift+F`): Search now sits in the Code sidebar
  next to the Explorer, with hits grouped under their file.
- Fixed: looking up a string in a dex file could miss it when it held
  characters outside the BMP (such as emoji) or an encoded NUL.

## Themes and settings (v0.4.0-beta.1)

- **Nine themes**: Dark Modern (the default), Light, High Contrast, Solarized
  Dark and Light, Nord, Dracula, Gruvbox Dark and One Dark. Every colour in the
  app comes from the theme, so panels, code, graphs, the hex view and the
  terminal always match; switching applies at once. Text in every theme meets
  the WCAG contrast guidelines.
- **Custom colours**: Settings > Appearance lists every colour of the theme,
  grouped and filterable. Changes preview live, survive a theme switch and
  can be reset one by one or all at once.
- **Reorganised settings**: General, Appearance, Editor, Decompiler, Android &
  Devices, Network Capture, Terminal & Scripts and AI (MCP), with a zoom slider
  on the Appearance page. Cancel or Esc undoes the preview.
- **Roomier layout**: more space between items, padded toolbar buttons, tab
  icons clear of the tab's accent line, and the Bookmarks filter uses the same
  chips as the other view switches. The title bar icon has a light version for
  dark themes.
- Fixed: **code search** over decompiled sources (`search_code` for AI
  assistants) crashed the app; search results no longer end in a stray
  carriage return on Windows.
- Fixed: the **Terminal** shell quit at once when ApkSpy was started from a
  script or IDE that redirects its output.
- Fixed: selecting a debugger thread without an attached app now reports an
  error instead of success.
- Code quality: no compiler warnings under MSVC /W4 or clang -Wall -Wextra
  -Wpedantic, and C++-style casts throughout.

## Workbench: terminal, command palette, icons

Researched against VS Code, JADX, Binary Ninja, Ghidra and IDA.

- **Terminal** panel (`` Ctrl+` ``): a real shell in a pseudo-terminal (ConPTY
  on Windows, forkpty elsewhere) with colours, scrollback, the alternate
  screen for full-screen programs, selection, copy and paste. It starts in the
  project folder with adb and jadx first on `PATH`. In every workspace but
  Analysis, beside Output or Logcat.
- **Quick open and command palette** (`Ctrl+P`, `Ctrl+Shift+P`): fuzzy search
  over every file, `>` for commands, `@` for classes and `:` for a line.
- **Icons** from the Windows icon font (Segoe Fluent Icons, or Segoe MDL2
  Assets on Windows 10) on panel tabs, the workspace switcher, the welcome page,
  the palette and buttons. Other systems keep text labels.
- **A darker, calmer theme** after VS Code's Dark Modern: side panels a shade
  darker than the code, a blue line on the selected tab, rounded inputs and thin
  scrollbars.
- **Breadcrumbs** above a file; click a folder to show it in the Explorer.
- Tab menu: **Reveal in Explorer**, **Copy Path**, **Copy Name**, **Keep Open**
  and **Close to the Right**.
- A **welcome page** with start actions, recent projects and the shortcuts.

## Video, and a round of fixes

- **Video** plays in the editor on Windows (MP4, 3GP, MOV, WebM, MKV, WMV, AVI,
  and AAC / M4A audio) through Media Foundation, with sound, a seek bar and
  volume. Very large pictures are scaled to 1920 pixels while decoding; a
  4500 x 3000 test clip went from frames of 54 MB each to 10 MB.
- Closing the last tab while a sound or video played left it playing; closed
  tabs now always stop.
- Attaching the debugger left Logcat on the previous device when another one
  was selected; it now follows the attached device.
- A finished decompilation no longer pulls the Explorer to the Decompiled tab
  while you are reading a file, or for an APK with no code.
- Search results containing `##` (Markdown headings, preprocessor lines) showed
  only part of the line.
- Hex viewer: the arrow keys move the cursor only, without keyboard navigation
  also scrolling the view.
- Format names for WebM, AVI, WMV and M4A.

## A clearer Analysis workspace

- **Analysis** is laid out like JADX, Ghidra and Binary Ninja: a navigator on
  the left with classes as a package tree and readable method signatures, the
  code in the center, and callers and callees of the selection along the
  bottom in the new **References** panel.
- Clicking a class or method opens its decompiled Java in a preview tab, at the
  method. The new **Function** panel shows the method's smali, control-flow graph
  or call graph, and native functions' listings and graphs.
- Query results (string uses, type references, resource ids) appear in
  References, with **<** to go back to the selection.
- Strings that contain control bytes show them escaped instead of as blank rows.

## Files

- **Audio** (WAV, MP3, FLAC, Ogg Vorbis) plays in the editor with a waveform,
  seeking and volume, using miniaudio.
- **Font files** show their name, sample text at five sizes and their glyphs.
- **Signature blocks** (`META-INF/*.RSA`) show the signing certificate.
- Audio and fonts are recognised by content too, and the Explorer has icons for
  audio, video and database files.

## Hex viewer

- Rewritten: column header, coloured bytes, range selection with the mouse or
  keyboard, copy as hex, text or a C array, find backwards, 8 / 16 / 32 bytes
  per row, relative and decimal Go to, the file's format, and a data inspector
  with big endian, binary, Unix time and UTF-16.

## Fixes and layout

- The workspace switcher sits at the bottom left of the status bar.
- A single click in the Explorer or Search opens a preview tab again instead of
  a new tab each time, when another file was already open.
- **Native**: the Sections view no longer reports an ID conflict (both of its
  rows had a "Sections" button).

## One output window

- **Output** now carries everything. Each line starts with its source, in its
  own colour: `[app]`, `[jadx]`, `[analysis]`, `[scripts]`, `[mcp]` or `[debug]`.
  A second dropdown shows one source at a time, and Warnings and Errors count all
  of them, not just jadx.
- **Scripts** print into Output, which now sits under the script editor, and they
  keep reporting while you work in another workspace. The editor gets the space
  of the old output pane, and runs add to the log instead of clearing it.
- The script editor has Python syntax colouring and line numbers, and `.py`
  files opened from an APK are coloured too.
- Output keeps 50,000 lines, up from 6,000, and no longer goes blank when old
  lines are dropped.
- The "Font atlas" message is gone.

## Responsiveness

Measured on a 50 MB APK with 15,782 decompiled sources.

- **Clicks answer sooner**: a tab's contents waited on the idle timer after a
  click, about 130 ms each time. They now appear in about 33 ms, because the
  app keeps drawing for a few frames after input.
- **Network** no longer freezes for half a second on first open: the strings
  behind the "In code" column are collected in the background, and the answers
  are remembered instead of scanning every string for every row on every frame.
- **Zoom**: a quick run of `Ctrl+wheel` or `Ctrl+=` steps waits for the last one
  before rebuilding the fonts (about 100 ms each time), and every step counts.

## A calmer interface

The rule for this pass: if it is not needed to do the job in front of you, it
moves to where you would look for it.

- **Shell**: the **View** menu replaces the row of workspace tabs, and the title
  shows the current one. Docks lost their menu triangles and close
  buttons, and a panel alone in its dock has no tab. A status bar shows the
  latest message and what is running; click it for the log.
- **Workspaces**: each keeps only what its job needs (Network is Traffic and
  Logcat, Scripts is the script editor).
- **Menus**: just File, View and Navigate. Analysis and debugging are driven from
  their workspaces, where the controls already were.
- **MCP** moved to File > Settings > AI (MCP); it is not something you work in.
- **Analysis** starts by itself when its workspace opens.
- Attaching the debugger starts Logcat, filtered to that process.
- **Analysis**: methods have no per-row buttons; double-click opens, right-click
  has the rest, `Space` opens the CFG and `X` the callers. Xrefs, Graph and
  Compare tabs appear only when they have something to show.
- **Native**: four views (Functions, Strings, Symbols, Sections) instead of seven
  radio buttons. The library list is a dropdown, and the first arm64 library
  opens by itself.
- **Graphs**: Fit and zoom sit on the canvas, with no hint lines above it.
- **Debugger**: keys in tooltips, and a stateful toolbar that only appears when
  attached. The breakpoint form moved into an **Add...** popup.
- **Devices**: no adb label or hint text; a lone device selects itself, and the
  options moved to a **...** menu.
- **Traffic**: **Start capture** replaces the proxy, port and routing controls.
- **Logcat**: one filter box (`text tag:Name pid:1234`) instead of three fields.
- **MCP settings**: three Copy buttons replace the config dumps.
- **Script**: scripts save themselves; the Python path moved to Settings > Scripts.

## Graphs, Python scripting and a round of fixes

### Graphs
- `analysis/GraphLayout`: layered layout (back edges, longest-path layers,
  barycenter crossing reduction, orthogonal routing), top-down or left to right.
- `ui/GraphView`: pan, zoom around the cursor, fit, selection with edge
  highlighting and a minimap. It replaces the old fixed bytecode CFG drawing.
- Control-flow graphs for arm64 functions (`NativeCode::controlFlow`, MCP
  `native_cfg`), with `Space` toggling listing and graph, following calls and
  jumps by double-click, and comments and bookmarks in the blocks.
- Call graphs for bytecode methods and native functions.
- `show_native` takes a `view`; new `show_method` opens a method's listing,
  CFG or call graph.

### Scripting
- **Script** workspace: edit and run Python scripts, with live output and Stop.
- `apkspy` module: every MCP tool as a function, over a private local endpoint.
  No embedded interpreter: scripts use the installed Python and its packages.

### Fixes
- Debug workspace: the editor stayed empty at a stop. It now opens the code
  there, on the exact instruction when the APK has been analysed.
- Native code views were squeezed: the library list becomes a dropdown there
  and the function list sits beside the code, or hides for graphs.
- Tail calls to unnamed code now create functions, so thin wrappers have callees.
- Entering a workspace focuses its main tool instead of whichever window came
  next, which could flip a dock tab.
- A detached debugger no longer reads `(running)`.

### Tests
- 232 checks: graph layout invariants (no overlaps, routed edges, cycles, a
  4000-block graph), native basic blocks, the script runner and the `apkspy`
  module under real Python.

## Workspaces

- Workspaces replace the single shared layout: **Code**, **Analysis**,
  **Debug**, **Network** and **AI**, each giving its main tool the central
  area. Switch with the tab row or `Ctrl+1` onwards.
- Each workspace has its own dock tree and window per panel, so arrangements
  are saved independently; panel objects, and so their contents, are shared.
  Panel visibility is per workspace; **Reset Workspace Layout** resets one.
- Tabs show live state: analysis running, debugger running or paused, sniffer
  capturing, MCP server on.
- Navigation switches for you: attaching the debugger opens Debug, Show in
  Logcat, Bookmarks and `show_panel` find a workspace with the panel, and a
  file opened without an editor in view goes to one that has it.
- The Debugger uses its new space: Threads, Call stack and Locals in three
  columns. Its stale-width resizers are gone, and the thread list drops the
  Susp column (now in the row tooltip) so names stay readable.
- The default layout is rebuilt once on upgrade; older layouts are not migrated.

## Bookmarks and comments

- `core/Annotations`: bookmarks and comments on file lines (APK and
  decompiled trees) and native addresses, stored in the project file with a
  sanity cap on untrusted counts, and removed with their APK.
- Viewer: line selection, right-click menu, **Ctrl+B**, **;**, gutter dots and
  inline comments. Native listing: the same actions, with orange addresses.
- New **Bookmarks** panel with filters, jump, edit, copy and delete.
- MCP: `list_annotations`, `add_annotation`, `remove_annotation`. The headless
  server writes annotation changes back to the project file on exit, changing
  nothing else in it.
- Unsaved annotations mark the project dirty.

### Bug fixes
- Right-clicking anywhere in a document opened the tab menu: the hover check
  ran after the document body and tested its last item instead of the tab.
- Saved tabs never reopened: `openProject` queued them after opening the APKs,
  so they were missed, and every reopened project with tabs looked unsaved.
- `OpenMode::Permanent` still produced preview tabs: `Document` defaults to
  preview and `openNode` only ever set it to true.

### Tests
- 204 checks (was 181): the annotation store, project round trip with
  multi-line text and 64-bit addresses, hostile project values, the MCP tools,
  removal with the APK, and permanent tabs.

## Native disassembly and deeper debugging

### Native code (arm64-v8a)
- `analysis/Arm64`: an AArch64 decoder for the base A64 integer, load /
  store (pairs, exclusives, atomics, register offsets), branch, system
  (hints, PAC, barriers, system registers) and scalar FP instructions plus
  the common Advanced SIMD groups (three-same, by-element, two-register,
  across-lanes, copy, modified immediate, ld1-ld4 / st1-st4). It renders
  objdump-style aliases (`mov`, `cmp`, `cset`, `lsl`, `uxtb`, ...). On
  Android's libc / libz / libblas it decodes 99.91 / 99.66 / 99.76 % of the
  instructions; the rest print as `.inst`.
- `analysis/NativeCode`: function discovery (symbols, PLT stubs named after
  their JUMP_SLOT relocation, call targets as `sub_<addr>`), one linear
  sweep that indexes calls, jumps, address-taken data (`adrp` + `add`,
  `adr`) and loads (`adrp` + `ldr`), annotated listings and string
  references. `ElfFile` now parses named relocations (REL / RELA) and
  demangles internal-linkage (`_ZL`) names.
- Analysis > Native gets **Functions** (list + listing with follow / back,
  callers, open in editor) and **Strings** views; the narrow layout keeps
  most of the height for the listing.
- MCP: `native_functions`, `disassemble_native`, `native_xrefs`,
  `native_strings` and the GUI tool `show_native`. Built code analyses are
  cached in `AnalysisService` (weak cache + the most recent library).

### Debugger
- Fixed: the call stack was always empty on ART - `ThreadReference.Frames`
  asked for 64 frames and ART answers INVALID_LENGTH when the stack is
  shallower; the depth is now queried first.
- Object values name their runtime class (`MainActivity@22`,
  `int[3]@23`), types read as Java (`int`, `long`, `String[]`).
- Locals expand objects (instance fields along the class chain) and arrays
  (first 200 elements); MCP `debugger_inspect`; locals carry `object_id`.
- Exception breakpoints (class or any, caught / uncaught) in the panel and
  through `debugger_breakpoint` `add_exception`; the stop reports throw and
  catch locations and exposes `$exception`.
- Readable call stack (`MainActivity.compute(int, String) : 43`) and
  Devices panel rows: double-click to debug or monitor, context menu with
  Attach / Monitor / Show in Logcat / copy.
- Verified end to end on an Android 15 emulator with a debuggable test
  app: attach, line breakpoints, stack, locals, object / array expansion,
  step over / out, exception breakpoints, resume, detach.

### Tests
- 181 checks (was 153): 36 pinned AArch64 encodings, NativeCode on a
  synthetic ELF (functions, xrefs, string resolution, ABI refusal,
  cancellation), JDWP fields / object values / array regions / exception
  requests against the fake peer, the native MCP tools end to end.

## Reverse-engineering platform: analysis, debugger, MCP

### Memory and performance
- **Documents** store their text in one buffer plus 4-byte line offsets
  instead of a `std::string` per line. A 5.8 MB / 150k-line file went from
  35.0 MB (Debug) / 14.9 MB (Release) to ~4.6-6.4 MB in both - the per-line
  strings each carried a debug-heap container proxy in MSVC Debug builds.
- **Font atlas**: the CJK fallback baked all 21k unified ideographs into
  both fonts and kept the alpha8 + RGBA32 pixel copies and both copies of
  the ~19 MB TTC in CPU memory after the GPU upload. The CPU copies are now
  freed after the upload and the common Chinese + Japanese subsets are
  baked by default (opt-in setting for full coverage). Idle GUI: 646 MB ->
  244 MB private memory, Debug and Release alike.
- `DiskSource::readFile` does one sized read (was a byte-wise
  `istreambuf_iterator` loop with geometric regrowth); `ApkArchive` inflates
  entries straight into the destination buffer and refuses declared sizes
  above a cap before allocating; the search reuses one read buffer; the
  symbol index stores every path once; tree building and the 1.5 s jadx
  merge use `string_view` keys and sort only folders that changed.
- Logcat (50k lines) and the process monitor use bounded ring buffers;
  analyses are released when their APK is removed or the project closes.

### Bug fixes
- Class and field searches bound a `std::string_view` to a temporary
  lowered copy of each line (dangling view, undefined behaviour) - the
  keyword scan is now done in place.
- "Don't Save" on an edited document blanked it (the views were rebuilt
  from the cleared edit buffer); it now returns to the original text.

### New
- `src/analysis`: DEX parser, Dalvik disassembler (all formats, payload
  pseudo-instructions), APK-wide xref index, call graph, CFG with exception
  edges, constant-argument data flow, class hierarchy, string heuristics,
  ELF parser with a small Itanium demangler, APK diff, background
  AnalysisService. Analysis panel with Classes / Xrefs / Strings / Graph /
  Native / Compare tabs; generated listings open as virtual read-only tabs.
- Hex viewer with offset jump, pattern search and data inspector.
- `src/debug`: shell-free adb wrappers, JDWP client, DeviceService with
  Logcat, CPU / memory / thread monitor and a debug session (threads,
  frames, locals, breakpoints incl. deferred class-load breakpoints,
  stepping). Devices, Logcat and Debugger panels; Debug menu with x64dbg
  shortcuts; Settings page for adb.
- `src/mcp`: JSON, MCP server core (JSON-RPC 2.0, schema validation,
  batching, cancellation, progress, owner-thread dispatcher), 35 tools,
  stdio and loopback HTTP transports, MCP Server panel, headless
  `--mcp` mode.
- `ChildProcess` moved from JadxRunner to `core/Process` (shared with adb);
  children are now created suspended and placed in their kill-on-close job
  before they run, and stdin is the null device.
- New portable test suite `apkspy_platform_test` (also a Visual Studio
  project in the solution).

## Window icon from assets/favicon.ico

- **New `assets/` folder in the solution directory** (next to `ApkSpy.sln`),
  shipped with a placeholder `favicon.ico` (green rounded square + white
  magnifier, 16/32/48 px 32-bpp BMP frames). Drop in any other `.ico` and
  restart to rebrand the app - no rebuild required.
- **Asset lookup (`pathutil::assetsFile`)** resolves `assets/<name>` next to
  the executable, then one and two levels up (covering both `build/` and
  Visual Studio's `x64/Debug` layouts), then the working directory. The
  executable directory comes from the new `pathutil::exeDir()`
  (`GetModuleFileNameW` / `/proc/self/exe` / `_NSGetExecutablePath`).
- **New `core/IcoLoader.{hpp,cpp}`** - a dependency-free ICO decoder for the
  app's own assets: classic BMP payloads (1/4/8/24/32 bpp, BI_RGB and
  BI_BITFIELDS, BITMAPINFOHEADER and the 12-byte BITMAPCOREHEADER, AND-mask
  transparency incl. the all-zero-alpha fallback) and PNG-compressed frames
  (inflated with the vendored miniz, no new dependency). Bounds-checked
  throughout; unusable frames are skipped with a reason instead of failing
  the file. `bestFrame()` picks the frame closest to a requested size.
- **Start-up hook (`Application::loadWindowIcon`)**: when `favicon.ico` is
  found and decodes, every frame is passed to `glfwSetWindowIcon` (window +
  taskbar pick their sizes) and the frame closest to 32 px becomes a
  `Texture` drawn in the custom title bar's icon slot (procedural glyph kept
  as fallback on other platforms or without the asset). A missing or bad
  asset is never fatal - a decode failure is logged to the Output panel.
- **Tests:** the core suite builds BMP (32/24/8 bpp) and PNG frames in
  memory and pins the decoded pixels, the AND-mask alpha rules, multi-frame
  decoding, `bestFrame` selection, the error paths and (when present) the
  shipped `assets/favicon.ico` itself.

## Daily-driver navigation, phase 1

### M1 - Find in file (Ctrl+F) and Go to line (Ctrl+G)
- **Find in file.** `Ctrl+F` in the editor opens a slim find bar above the
  document: query field, match-case (Aa) and whole-word (W) toggles,
  prev/next, a `n of m` counter (`No results` in the error colour when the
  query has no matches, `10000+ results` when the list was capped) and a
  close button. `Enter`/`F3` jump forward, `Shift+Enter`/`Shift+F3` backward,
  both wrapping; `Esc` closes the bar and returns focus to the editor. Every
  visible match gets a translucent background, the current one a stronger
  one - in the read-only viewer and in the syntax-highlighted editor alike.
  Matches are recomputed only when the query, the options or the document
  text change (`Document::textRevision()`), never per frame.
- **Go to line.** `Ctrl+G` opens a small popup "Go to line (1-N)"; input is
  clamped to the valid range and the jump reuses the existing
  goTo/highlight machinery.
- **Selection prefill.** Selecting text in the editor and pressing `Ctrl+F`
  pre-fills the find bar with it (single-line selections only).
- **New `core/TextSearch.hpp`** - pure, headless-testable search: 0-based
  lines, byte columns, ASCII-only case folding via `tex::asciiLower`
  (UTF-8 bytes are never touched), whole-word detection through the shared
  identifier-char helper in `TextUtils.hpp` (no second copy in the code
  base), overlapping matches, a configurable result cap and wrap-around
  next/prev helpers.
- **Menu:** View > Find... and View > Go to Line... live in the shared menu
  function (both the ImGui menu bar and the custom title bar offer them) and
  are disabled when no code document is active. `Ctrl+F` is scoped to the
  Editor window, so it never steals the shortcut from a text field in
  another panel.

### M2 - Back / Forward navigation
- **Alt+Left / Alt+Right** (and mouse buttons 4/5, plus `‹ ›` buttons at the
  left of the editor toolbar) walk an editor-wide navigation history like an
  IDE. Explicit jumps are recorded: opening a search hit, opening a file from
  the Explorer while a document is active, Go to Line and (from M3) symbol
  navigation. Plain tab clicks do not create entries.
- **Back returns exactly where the user was**: before every jump the origin
  (active document + top visible line) refreshes its history entry, so
  scrolling after a jump is not lost. An origin the history does not track
  becomes its own entry.
- **Closed or removed targets never crash**: navigating to a location whose
  tab was closed re-opens it (permanent tab, same group/kind/path); entries
  whose file or APK no longer resolve are skipped with a one-line note in the
  Output panel. `Remove from Project` purges the removed group's entries,
  `closeAll` clears the history (it is per project session, never saved).
- **New `core/NavHistory.hpp`** - pure cursor semantics (vector + index):
  forward-stack truncation, duplicate suppression, max-size trimming,
  group purge. `Workspace::navigateTo/navBack/navForward` wire it up;
  `Document::viewLine()` (plain UI view state) feeds the "where was I" line.
- **Menu:** View > Navigate Back / Navigate Forward in the shared menu
  function, enabled state reflecting `canBack()/canForward()`.

### M3 - Click-to-navigate (Ctrl+click a class -> open its file)
- **Ctrl+click any identifier** in the read-only code view opens the file
  that declares it: the identifier under the cursor is resolved against a
  per-APK symbol index and the class file opens as a history-recorded jump
  (Alt+Left returns). While Ctrl is held the identifier under the cursor is
  underlined, so the target is visible before clicking. Unresolved
  identifiers (keywords, framework classes) log a quiet one-liner in the
  Output panel instead of doing nothing silently.
- **New `core/SymbolIndex.{hpp,cpp}`.** The index maps short names
  (`Foo`), nested names (`Bar` from `Foo$Bar.java`) and fully qualified
  names (`com.example.Foo`) to files. Same-package files win when several
  classes share a simple name (the click's directory is the hint). The
  builder runs on a worker thread: the UI thread snapshots the candidate
  file list from the tree only while that group is idle (never against a
  live tree), the worker reads plain files via `ContentSource` - the
  threading rules of the code base are untouched.
- **Workspace epoch:** every change to a decompiled tree bumps a per-group
  epoch; the index rebuilds exactly once per change (decompile finished,
  re-attached results) and is purged with the group.
- Same machinery is used by the Overview panel (M4) to jump from a manifest
  component row to its class, with a graceful fallback when the class is
  not in the decompiled sources (e.g. androidx components).

### M4 - APK overview panel (manifest, permissions, components, signing)
- **New Overview panel** (docked as a tab next to the Explorer): identity
  header (label, package, version name/code, min/target SDK, `debuggable` /
  `allowBackup` badges), the declared permissions, every component
  (activity, activity-alias, service, receiver, provider) with its
  intent-filter actions/categories as a tooltip, and the signing
  certificates.
- **Components jump to their classes** through the M3 symbol index
  (relative `.Main` and bare names are qualified against the package);
  when the class is not in the decompiled sources (framework/library
  code), the manifest opens instead and a log line explains why - the
  graceful fallback the overview table asked for. A manifest row opens the
  binary manifest directly.
- **Signing:** v2 (0x7109871a) and v3 (0xf05368c0) blocks are parsed from
  the APK Signing Block (located via the EOCD, tail reads included); v1
  (JAR) certificates come from top-level `META-INF/*.RSA|DSA|EC` entries.
  Each certificate is reported with its full-DER SHA-256 fingerprint and
  the subject/issuer Common Name. Unsigned APKs say so.
- **New files:** `core/Sha256.hpp` (self-contained FIPS 180-4 SHA-256),
  `core/Der.hpp` (minimal bounds-checked DER walker: TLV, OIDs, X.509
  CommonName), `core/ApkInfo.{hpp,cpp}` (manifest + signing extraction,
  UI thread only - it reads through the APK's `ContentSource`),
  `ui/OverviewPanel.{hpp,cpp}` (panel + registry entry in Application).
- **AxmlDecoder is extended additively:** a new `decodeEvents(bytes,
  Visitor&, error)` event walk feeds structured consumers; `decode()` is
  now a thin printing visitor on top of the same walk, so the text decoder
  and structured consumers can never disagree about the format. The text
  output is byte-identical (pinned by the existing tests).

### M5 - Export / extract (single file, folder, raw vs decoded)
- **Explorer context menu:** files offer **Export Raw...** (exact bytes)
  and **Export Decoded...** (compiled Android XML becomes readable XML
  text); folders offer **Export Folder (raw)...** and **Export Folder
  (decoded)...** which copy the whole subtree into a picked directory.
- **Editor toolbar Export...** saves the active document: the exact bytes,
  or the current edit buffer when the code document has unsaved edits
  (what you see is what gets written).
- **New `core/SafePath.hpp` - the zip-slip sanitiser** (ground rule 5):
  every file name that originates from archive content passes through it
  before a file is written. Absolute paths lose their root, `..` segments
  and dots-only names are neutralised, drive letters and control characters
  are defused, Windows reserved device names (CON, NUL, COM1...) get a
  '_' prefix and trailing dots/spaces are stripped. A containment check
  after the join verifies the guarantee.
- **New `core/ExportJob.{hpp,cpp}`:** cooperative folder export, one item
  read+written per `Workspace::update()` frame **on the UI thread** - the
  only thread allowed to call `ContentSource::read` on an APK root, so the
  threading invariants stay intact. Progress (name, done/total, failures)
  and a Cancel button are shown at the bottom of the Explorer. Cancelling
  an APK removal / project close also cancels a running export whose items
  point into the affected trees.
- **FileBrowser:** new `SaveFile` (export target, any name) and
  `SelectFolder` (directory picking with a highlighted folder) modes.

## Security, robustness and performance overhaul
- **Project files can no longer point ApkSpy at arbitrary directories.** The
  jadx output directory is always derived from the APK itself (path, size and
  mtime are hashed into `<temp>/apkspy/<name>_<hash>`); the `jadxOut` key
  inside a `.apkspy` file is ignored on load. Every cache directory carries a
  marker file - only directories ApkSpy created are ever deleted
  recursively, and only by the marker.
- **jadx runs without a shell.** The child process is started with an argv
  array (posix_spawn / CreateProcessW with proper quoting), so paths can
  never inject commands. `.bat` launchers go through `cmd.exe` on Windows;
  non-ASCII paths work everywhere (internal strings are UTF-8, converted at
  the OS boundary - the APK is opened via `_wfopen`, decompiled files via
  wide `ifstream`).
- **Cancellation.** A running jadx can be cancelled (button next to the
  progress bar); the whole process tree is terminated (process group on
  POSIX, Job Object on Windows) so a launcher script can no longer orphan
  its java child and hang the exit. Shutdown kills a running decompile
  instead of waiting for it.
- **No more stale decompiled results.** A completion marker is written only
  when jadx exits cleanly; partial output from a killed or crashed run is
  re-run instead of being re-attached. Two APKs with the same file name
  (e.g. two `base.apk`) never share a cache directory.
- **The search data race is fixed.** Searching a tree that is currently
  receiving jadx output is refused (and an in-flight search on it is
  stopped) - the UI thread mutates those trees while results stream in.
- **Closing the window no longer discards unsaved work.** The title-bar X,
  Alt+F4 and File > Exit all route through the unsaved-changes confirmation.
- **AXML decoding matches the AOSP layout.** `attributeStart` is now
  interpreted relative to the attrExt struct (real files store 20, not 36),
  which previously garbled every attribute on real manifests. The complex
  value math matches AOSP exactly (2^-23 radix multiplier, signed mantissa -
  negative dimensions like `-4dp` print correctly), the FLOAT type-punning
  is gone and a UTF-16 string-pool over-read is closed.
- **Clicking a search hit jumps to the matching line again** - in both the
  read-only viewer and the editor, with the line highlighted.
- **Explorer selection persists** (the row highlight and Ctrl+C previously
  only lasted a single frame), and the tree is **virtualized** (flat rows +
  clipper) so packages with thousands of classes scroll smoothly. Folder
  merges during decompilation and APK tree building use per-folder indexes
  instead of quadratic scans.
- **Tabs no longer jump to the end** when their label gains or loses a
  " *"/" (preview)" marker (stable `###doc` ids).
- **Output panel filter fixed**: the severity filter no longer corrupts the
  list (rows are indexed, not skipped inside the clipper) and auto-scroll
  only engages while you are already at the bottom. jadx severity lines are
  classified once, by one shared classifier (a class named `ErrorHandler`
  no longer counts as an error).
- **Read-only viewer by default**: documents open in the fast clipper view;
  an **Edit** toggle above the document switches to the in-place editor
  (unsaved edits are kept when toggling back). Keystrokes re-parse lazily
  instead of re-tokenizing the whole file per character.
- **Missing APK files no longer flag the project as dirty forever** - the
  entries stay in the project (and in the saved file) instead of being
  silently dropped by the next save. Project loading bounds the entry
  counts of untrusted files.
- **Settings and dock layout live in the per-user config directory**
  (`%APPDATA%\ApkSpy`, `~/.config/apkspy`, `~/Library/Application Support/ApkSpy`)
  and are imported from the old working-directory copies on first start.
  Settings are written atomically (temp file + rename), sorted, and parsed
  CRLF-safely.
- **Fonts cover Latin, Greek, Cyrillic and common CJK** and scale with the
  monitor content scale (rebuilding live on DPI changes). The app renders
  continuously while jadx or a search runs and otherwise waits for input.
- **Images from untrusted APKs are bounds-checked** (header probed via
  `stbi_info` / WebP features) before decoding, so crafted dimensions
  cannot allocate gigabytes. APK entries with long names are no longer
  truncated (single `file_stat` path), and "Remove from Project" now also
  deletes the decompiled cache directory it owns.
- **Working tests again.** The Makefile recipes use real tabs (the build was
  broken as shipped) and `make test` runs two headless suites: core logic
  (decompile, cancel, re-attach, markers, projects, AXML, search, settings)
  and ImGui regressions (caret overlay geometry vs. ImGui's own caret,
  stable tab ids).
- MSVC project cleanups: Debug uses the real debug CRT again (no
  `_ITERATOR_DEBUG_LEVEL=0`), the console window is gone (SubSystem
  Windows), warnings are at /W4, and miniz is compiled as C in tests.
- Dead code removed (`closeMany`, unused `Save` tooltip, `Mode::OpenApk`,
  `SearchService::modeName`, write-only fields, the `&& false` condition in
  the smali tokenizer, ...); the six copies of ASCII-lowercasing and the two
  disagreeing log classifiers were unified into shared helpers
  (`core/TextUtils.hpp`, `core/LogSeverity.hpp`).

## Projects, multi-APK support and Explorer cleanups
- **Projects** are here. A project (`.apkspy` file) stores the APK list,
  the permanently opened tabs and project configuration. (The jadx output
  location later became derived - see the security overhaul above.) The **File** menu is now: New Project, Open Project
  (Ctrl+O), Recent Projects, Add APK(s) to Project..., Save Project (Ctrl+S,
  the only save command - it also writes edited files to disk), Close Project
  and Exit. Menu items that need an open project are disabled, and closing,
  switching or exiting with unsaved changes asks first.
- **Multiple APKs per project**: adding APKs no longer resets the workspace -
  every APK becomes its own group. Decompile runs are queued (one jadx at a
  time). The **Files** and **Decompiled** tabs use the same unique group name
  per APK (identical filenames become "name (2)"), so output never mixes.
- **Decompiled tab simplification**: only the `sources` tree is shown per
  APK (still with its full hierarchy); `resources` no longer appears - it
  stays on disk and remains available through the Files tab where present.
- **Remove from Project**: right-click an APK root in the Explorer. It
  removes the APK reference, its decompiled results and related tabs (with a
  confirmation); the APK file on disk is never deleted.
- **Text selection in the Explorer**: click-and-drag selects rows (opening a
  file is deferred to mouse release so drags select instead of opening),
  Ctrl+C copies the selected items' names, single/double click behaviour is
  unchanged. Clicking empty space clears the selection.
- The **Tools menu** is gone; Settings moved to **File > Settings** (Ctrl+,).
  The **Reopen Closed Tab** feature (Ctrl+Shift+T, tab context-menu entry and
  its workspace stack) was removed.
- Reopening a project re-attaches existing jadx results from disk without
  re-running jadx; missing APK files are reported in the Output panel.
- The Search panel gets an APK selector when a project contains several
  decompiled APKs; search results are cleared when their APK is removed.

## Editor caret fix
- Fixed the **invisible typing cursor**: the editor draws its own caret on top
  of the syntax overlay, but the code located the input widget's internal
  child window with `FindWindowByID(widgetId)` - and ImGui names that window
  `<parent>/##edit_<id>` (its id is the hash of the full string), so the
  lookup always returned NULL and the caret was never drawn. The window is
  now resolved by the exact name ImGui generates, which also fixes the syntax
  overlay following the view when the editor is scrolled.
- Verified with a headless ImGui reproduction (click + type simulation): the
  caret geometry now matches ImGui's own caret placement to the pixel.

## Windows default icons in the Explorer
- The Explorer now shows the **real Windows default icons** (the exact ones
  Explorer itself uses) next to every file and folder: folders get the shell
  folder icon, files get the icon registered for their extension, and the APK
  root gets the system's `.apk` association icon. Extensions without an
  association fall back to the generic file icon.
- Icons are extracted from the shell via `SHGetFileInfo` (with
  `SHGFI_USEFILEATTRIBUTES`, so nothing is read from disk) and cached as GL
  textures **once per file extension** - the first frame a new file type
  appears does one extraction; afterwards it is a plain texture draw, with
  no per-frame cost and no load-time hit.
- Linux/macOS builds keep the previous built-in drawn icons as fallback.

## One-view editor & UI cleanup
- The **Read-only view** is gone completely. Files are edited in a single view
  that keeps their syntax colours while typing: the text input renders the
  caret, selection, clipboard, undo/redo and all editing keys, and a
  highlighted overlay (same font, same scroll position) paints the coloured
  text on top. The Edit button is gone too.
- The **Decompiled tab** is back by popular demand: the Explorer has two tabs,
  **Files** (the APK archive contents) and **Decompiled** (the jadx output tree,
  browsable live while jadx runs, with the progress bar on top). When a
  decompilation finishes the UI switches to the Decompiled tab automatically.
- Renames: dock panel **Assembly Explorer** -> **Explorer**; tab **APK
  Explorer** -> **Files**. (Existing `apkspy.ini` layouts keep working; the
  Explorer may appear undocked once - use View > Reset Layout to restore.)
- Unsaved-change indicator stays a star (`*`) and saving stays on **Ctrl+S**;
  APK entries that cannot be saved still open as highlighted read-only
  documents.

## Editor workflow & file support
- Files on disk are now **editable as soon as they open** - the Edit button is
  gone. A small **Read-only view** button (only shown while there are no
  unsaved edits) switches back to the syntax-highlighted view.
- The **Save** button is gone: save with **Ctrl+S**. Modified tabs are marked
  with a star (`*`) in the tab title instead of a dot.
- Removed the "(preview tab - double-click to keep open)" hint from the editor
  toolbar; the tab title still says "(preview)".
- **Binary XML support**: APK entries like `AndroidManifest.xml` and
  `res/**/*.xml` are compiled AXML and used to open as hex bytes. They are now
  decoded into readable, indented XML (namespaces, string/int/bool/reference/
  dimension/color attribute values) and shown as normal XML documents.
  A new `AxmlDecoder` handles the binary chunk format.
- More text file types are recognized instead of falling back to hex/binary
  coloring: `.pro .sh .bat .cmd .py .c/.h/.cc/.cpp/.cxx/.hpp/.hxx/.m/.mm
  .aidl .scala .go .rs .rb .pl .lua .php .toml .csv .tsv .log .sql .conf
  .list .prop`, plus extension-less `LICENSE`, `NOTICE`, `README`,
  `CHANGELOG`, `AUTHORS`, `CONTRIBUTING`, `Makefile`, `Dockerfile`.

## Context menu & Browse fixes
- Fixed the explorer context menu showing every option cloned multiple times.
  The popup used one fixed id (`##explorer_ctx`) shared by all tree nodes, so
  while the menu was open each node began the same popup and appended its
  items again. The popup is now tied to the clicked node's own item id.
- Fixed the **Browse...** button in Tools > Settings doing nothing. The file
  browser opened its popup in one ImGui ID scope (inside the Settings page)
  and rendered it in another (top level), so the modal never matched. The
  open request is now consumed inside `FileBrowser::render()`, in the same ID
  scope as the modal it begins; the Open APK browser keeps working as before.

## Project layout & tab fix
- Restructured the project: the application headers now live next to their
  sources in `src/<module>/` (internal includes changed from
  `#include "apkspy/..."` to `#include "<module>/..."`).
- `include/` and `lib/` now contain external dependencies only, one folder per
  library with the same name in both: `include/imgui`, `include/glfw`,
  `include/miniz`, `include/libwebp`, `include/stb` for headers and
  `lib/imgui`, `lib/glfw`, `lib/miniz`, `lib/libwebp` for sources/binaries.
- Fixed the Assembly Explorer tab bar: clicking **Decompiled** flashed its
  content and snapped back to **APK Explorer**. The tab selection was
  re-asserted every frame from a mirrored variable (`ImGuiTabItemFlags_SetSelected`),
  which re-queued the old selection before the clicked tab's content ran.
  Selection is now ImGui-driven; a one-shot request still auto-switches to
  **Decompiled** when a decompilation finishes.

## Settings & jadx configuration
- The jadx executable path moved out of the Open APK dialog into a dedicated
  Visual-Studio-style **Tools > Settings** dialog (`Ctrl+,`) with Environment /
  JADX / Text Editor pages.
- New **Browse...** button (built-in file browser, works on all platforms) and a
  **Test installation** button that runs `jadx --version` and reports the result.
- Extra jadx command line arguments can be configured.
- The **Open APK** dialog is now focused on selecting and opening APK files only
  (path + Browse + file-size feedback).
- User preferences, panel visibility and the dock layout are saved between
  sessions (`apkspy.settings` + `apkspy.ini`).

## Explorer
- The Assembly Explorer now has two tabs: **APK Explorer** (original archive
  contents) and **Decompiled** (jadx output) in a tree structure.
- jadx progress: indeterminate progress bar, elapsed time, warning and error
  counters; warnings (yellow) and errors (red) also appear in the Output panel
  with a severity filter and a Clear button.
- The Decompiled tree grows live while jadx runs, so partially generated
  results can be browsed and opened immediately.
- The UI switches to the Decompiled tab automatically when results are ready.
- Right-click context menu on explorer items: Open, Open in New Tab, Copy Path.

## Editor tabs
- Single-click opens a preview tab (labelled `(preview)`); further single clicks
  replace its content. Double-click promotes it to a permanent tab, and
  double-clicking a preview tab also promotes it.
- Permanent tabs stay open when other files are selected.
- Tabs close via the X button, middle click or the context menu, which offers
  Close, Close All, Close Others and Reopen Closed Tab (`Ctrl+Shift+T`).
- Modified files show a `•` marker; closing them asks for confirmation
  (Save / Don't Save / Cancel). Decompiled files can be edited and saved
  (`Ctrl+S`); APK entries are read-only.
- Open tabs and their state are remembered and restored with the project.

## Search
- New modes: Full text, Filenames, Classes, Methods and Fields over the
  decompiled output; hits open at the matching line (single-click preview,
  double-click permanent).

## Editor
- Syntax highlighting for Java, Kotlin, XML, JSON, smali, Groovy/Gradle, YAML,
  HTML, JavaScript and CSS.
- Optional line numbers (Settings > Text Editor).
- Explorer, Editor, Output (and Search) panels remain freely resizable,
  collapsible and dockable; View > Reset Layout restores the defaults.
