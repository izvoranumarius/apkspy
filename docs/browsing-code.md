# Browsing code

The **Code** workspace is where you read an APK.

## Explorer

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

## Editor tabs

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
- **Find in file** (`Ctrl+F`) opens a slim bar above the document with match-case and whole-word toggles, prev/next (`Enter`/`F3`, `Shift` for backward), a hit counter and per-tab state; matches are highlighted in both the viewer and the editor. **Go to Line** (`Ctrl+G`) jumps to a 1-based line number. Both are also in the **Navigate** menu.
- Open tabs and the panel layout are remembered between sessions; use **View > Reset Workspace Layout** to restore the current workspace's default layout.

## Overview

The **Overview** panel shows one APK at a time (selector when the project has several): app label, package, version, min/target SDK, `debuggable`/`allowBackup` badges, the declared permissions, all manifest components and the signing certificates (v1/v2/v3 with SHA-256 fingerprints and subject/issuer). Clicking a component jumps to its class in the decompiled sources; if the class is not there (framework code), the manifest opens instead.

## Search

The Search panel covers the decompiled output with five modes: **Full text**, **Filenames**, **Classes**, **Methods** and **Fields**. Single-click a hit to preview it, double-click to keep it open; the file opens **at the matching line** (the line is highlighted). With several APKs in the project a selector picks which one to search; a search is suspended while that APK is still being decompiled. Hit excerpts are capped in length, the result list at 3000 hits, and files above 4 MB are skipped (both are reported in the panel).

## Output

One window for everything the app reports. Each line starts with its source, in
its own colour: `[app]`, `[jadx]`, `[analysis]`, `[scripts]`, `[mcp]` or
`[debug]`. Warnings are yellow and errors red.

The two dropdowns filter by level and by source. Lines are selectable (click,
Shift+click, drag, Ctrl+A) and copy with Ctrl+C or the context menu. The view
follows new lines unless you have scrolled up to read. Output keeps the last
50,000 lines.

jadx exits with an error as soon as any class fails, but a run like that keeps
everything it did decompile.

## Supported formats

- **Source highlighting**: Java, Kotlin, XML, JSON, smali, Groovy/Gradle, YAML,
  HTML, JavaScript, CSS and Python.
- **Images**: JPEG, PNG, GIF, BMP, TGA, PSD, HDR, PNM and WebP (first frame of
  animated files).
- **Fonts** cover Latin, Greek, Cyrillic and common CJK characters and scale with
  the monitor DPI.

## Bookmarks and comments

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

## Hex viewer

Binary files (DEX, native libraries, anything that is not text or an image)
open in the hex viewer: jump to an offset, search hex patterns
(`64 65 78 0a`) or text with wrap-around, click a byte to select it, and the
**data inspector** shows the value at the selection as signed / unsigned 8-,
16-, 32- and 64-bit integers, float, double, ULEB128 and ASCII.
