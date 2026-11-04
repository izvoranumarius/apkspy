# Analysis

Opening the **Analysis** workspace parses every `classesN.dex` on a background
thread with progress and Cancel. The
analysis needs no jadx and works on obfuscated or partially broken APKs
(every offset is bounds-checked; malformed structures are skipped).

- **Classes** - every class (filterable, virtualized) and its methods with
  size. Double-click a class or method to open its smali disassembly as a
  read-only tab (find, go to line and Back/Forward work as for any file).
  Right-click a method for its callers, callees and control-flow graph, or use
  `Space` and `X` on a hovered method. Right-click a class for the decompiled
  source, type references and the class hierarchy.
- **Xrefs** - results of the last query (callers, callees, string or type
  uses); click a row to jump to the exact instruction.
- **Strings** - the DEX string tables with heuristics for URLs, IP
  addresses, API paths, secrets / tokens and e-mail addresses; click a
  string to list the code using it.
- **Graph** - see [Graphs](#graphs). **Copy DOT** exports Graphviz.
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

## Graphs

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

## Resources

`resources.arsc` is parsed when first needed: decoded binary XML (manifest,
layouts) shows `@string/app_name` instead of `@ref/0x7F0E0023`, the Overview
shows the real app label, and the **Resources** tab of Analysis lists every resource
(id, type, name, default value, number of configurations) with a type filter
and search. Right-click a resource for its id / reference, or (after the
bytecode analysis) **Find code using this id**, which lists the methods that
pass the id to a call.
