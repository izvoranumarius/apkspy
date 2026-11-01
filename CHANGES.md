# Changelog

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
