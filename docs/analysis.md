# Analysis

Opening the **Analysis** workspace parses every `classesN.dex` on a background
thread with progress and Cancel. The analysis needs no jadx and works on
obfuscated or partially broken APKs (every offset is bounds-checked; malformed
structures are skipped).

The workspace is laid out like JADX, Ghidra and Binary Ninja:

| Panel | Where | Shows |
| --- | --- | --- |
| **Analysis** | left | the navigator: Classes, Strings, Native, Resources, Compare |
| **Editor** / **Function** | center, as tabs | the decompiled Java; the selected method or native function |
| **References** | bottom | what calls the selection and what it calls, or the last query's results |

- **Classes** - a package tree (single-child packages are joined, as in
  `com.google.android`), with classes and their methods in readable form
  (`onCreate(Bundle) : void`). Type to filter by name or package. Clicking a
  class opens its Java in a preview tab, and clicking a method opens the Java
  at that method; without jadx output the smali is shown instead. Double-click
  keeps the tab. A method also fills **Function** (its smali, control-flow graph
  or call graph; `Space` switches between listing and graph) and
  **References**. Click a caller or callee there to go to it; callees outside
  the APK are dimmed. Right-click a class for its smali, type references and
  hierarchy, and a method for its graphs or smali in the editor.
- **Strings** - the DEX string tables with heuristics for URLs, IP
  addresses, API paths, secrets / tokens and e-mail addresses. Control bytes
  show escaped (`\0`, `\n`). Click a string to list the code using it in
  References; **<** goes back to the selection.
- **Graph** (in Function) - see [Graphs](#graphs). **Copy DOT** exports Graphviz.
- **Native** - `lib/<abi>/*.so`: ELF class / machine / SONAME / NEEDED,
  JNI entry points, exports and imports (demangled), sections and segments,
  and the hex view. For arm64-v8a libraries two more views:
  - **Functions** - every function (symbols, PLT import stubs named
    `name@plt`, and call targets without a symbol as `sub_<addr>`). Selecting
    one shows its AArch64 disassembly in **Function** and its callers and
    callees in **References**. Calls and jumps are named, `adrp` + `add` /
    `ldr` pairs are resolved to the string literal, GOT slot or symbol they
    address, and local branch targets are highlighted. Double-click a call or
    jump to follow it, Backspace / **<** goes back, and right-click offers
    **Open listing in editor**. Double-click a JNI / export symbol to
    disassemble it.
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
