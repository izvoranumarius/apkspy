# Analysis

Opening the **Analysis** workspace parses every `classesN.dex` on a background
thread with progress and Cancel. The analysis needs no jadx and works on
obfuscated or partially broken APKs (every offset is bounds-checked; malformed
structures are skipped).

The workspace is laid out like Cutter (and JADX, Ghidra, Binary Ninja):

| Panel | Where | Shows |
| --- | --- | --- |
| **Analysis** | left | the navigator: Classes, Strings, Native, Resources, Compare |
| **Function** | center | the selected method or native function: listing, control-flow graph or call graph |
| **Behavior** | center, a tab | what the app does: components, call paths, permissions, endpoints, storage, native code (see [Behavior graph](#behavior-graph)) |
| **Diff** | center, a tab | two versions of the app compared (see [Comparing versions](#comparing-versions)) |
| **References** | under Function | what calls the selection and what it calls, or the last query's results |
| **Decompiler** / **Editor** | right, as tabs | the selection decompiled (see [Decompiler](#decompiler)); jadx's Java |

- **Classes** - a package tree (single-child packages are joined, as in
  `com.google.android`), with classes and their methods in readable form
  (`onCreate(Bundle) : void`). Type to filter by name or package. Clicking a
  class opens its Java in a preview tab, and clicking a method opens the Java
  at that method (in the Editor tab behind the Decompiler); without jadx output
  the smali is shown instead. Double-click keeps the tab. A method also fills
  **Decompiler** and **Function** (its smali, control-flow graph
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
- **Compare** - opens the **Diff** panel (see [Comparing versions](#comparing-versions)).

The analysis of an APK is freed when it is removed from the project or the
project is closed.

## Decompiler

The **Decompiler** panel works like Cutter's decompiler pane. It shows what
**Function** shows, decompiled by ApkSpy's built-in engines. No jadx or Ghidra
is needed.

- **Dalvik methods** come out as Java-like code: calls, field and array
  accesses, `new T(args)`, casts, string / class constants, `null` / `true` /
  `false` where the uses say so, and try ranges with their catch handlers.
- **arm64 functions** come out as C-like code: named calls with their argument
  registers, indirect and tail calls, `adrp` pairs resolved to strings and
  symbols, typed loads and stores, stack slots as `sp_<off>` and comparisons
  rebuilt from `cmp` / `tst` / `ccmp` + `b.cond`, `csel`, `cbz` and `tbz`. The
  frame setup (saving and restoring registers, adjusting `sp`) is hidden.

Both engines fold single-use temporaries into expressions and drop dead
assignments. The control flow is structured into `if` / `else` (with `&&` /
`||` chains), `while` and `switch`. Where the graph has no structured form,
the output uses labelled `goto`s. Registers keep their names (`v3`, `arg0`,
`x19`, `w8`), and no types are inferred beyond what the instructions say.

Lines and instructions stay linked in both directions. The line holding the
listing's current instruction is highlighted. Clicking a line moves the
listing (or graph) to that line's first instruction, and the tooltip lists
the line's instructions. Double-clicking a line with a call goes to the
called method or function. Right-click copies the line or the whole function.
As in IDA's pseudocode view, every variable is declared with a type. The
parameters are typed in the signature, and the locals are declared at the top
of the body. Types are inferred from the code: field and return types, `new`,
casts and constants for Dalvik; register width, load size and string or
symbol addresses for native code (`int32_t`, `uint8_t`, `char *`). When a
register is reused for values of different types, it is declared `var` (or
`Object`) with a comment listing what it holds.

The panel has a text cursor, like IDA's:

| Key | Action |
| --- | --- |
| click, arrows, Home / End, Page Up / Down | move the cursor; the identifier under it is highlighted everywhere, and the listing follows the line |
| **N** | rename the variable under the cursor |
| **Y** | set the type of the variable under the cursor |
| Enter, double-click | follow the call on the line (double-clicking a variable renames it) |
| Esc | clear the highlight |

The same actions are in the right-click menu, which also has **Reset name**
and **Reset type**. An empty name or type restores the original. Names and
types belong to the method or native function and are saved with the project.
They apply to the registers and stack slots the output names (`v3`, `arg0`,
`x19`, `d0`, `sp_10`); `w8` and `x8` are the same variable. Names that are
keywords or already used in the function are refused. Types are free text,
since the output is pseudocode for reading: `struct conn *`, `unsigned int`,
`void (*)(int)` or anything else on one line. **Y** on a declaration sets that
variable's type, and **Y** on the signature line sets the function's return
type. Drag to select text (double-click a word) and copy it with `Ctrl+C`.

Strings that decode to readable text (Base64, hex, URL-encoded, JWT, gzip,
UTF-16...) get a `// decoded: "..."` note after the line, and hovering any
string literal shows its decoded form. Right-click > **Send string to Decoder**
opens it in the Decoder panel with the steps that decode it. Native code shows
UTF-16 strings as `u"..."`.

**Auto Refresh** (on by default) follows the selection. Turn it off to keep
a function on screen while you browse, then press **Refresh** to load the
current selection. The same output, with the same names, is available over
MCP as `decompile_method` and `decompile_native`, which also list the
variables with their types. MCP clients rename and retype with
`rename_variable` (`name` and/or `type`), and the panel updates live.

## Java and smali side by side

With **Java sync** on (in the Function header, on by default), jadx's Java
in the Editor and the smali in Function follow each other:

- Click a line of Java: its method becomes the selection (Function,
  References and Decompiler follow) and the line's instructions are
  highlighted in the listing. Lines inside a lambda go to its
  `lambda$<method>$N` method, lines inside an anonymous class to `Outer$1`,
  `Outer$2`... as javac numbers them.
- Click an instruction: the Java file, if it is open, highlights the line
  the instruction belongs to. No tab is opened for you.

Where jadx wrote debug line comments (add `--add-debug-lines` to the jadx
arguments in Settings > Decompiler) and the dex has line numbers, the mapping
is exact. Otherwise ApkSpy matches what each line and each instruction does,
in evaluation order: calls, `new`, `this(...)` / `super(...)`, string
constants, field accesses, branches, returns, throws and switches. A call
that appears twice maps to the right occurrence, and the instructions that
prepare a statement (constants, moves, `new-instance`) belong to it. Lines
with nothing to match, such as a closing brace, map to nothing. The header
says how a match was made. Selecting a method also opens the Java at the
right overload. MCP clients use `map_java_smali` for the same mapping.

## Behavior graph

**Behavior** maps what the app does, starting from the manifest. Every
activity, service, receiver and provider is walked through the code it
reaches: its own methods (and inherited app methods), what they call, and the
callbacks of the listeners, `Runnable`s and lambdas they create. Calls into
known libraries (OkHttp, AndroidX, Firebase... about a hundred are
recognised) are treated as API calls rather than walked. Each reached method
is classified by what it touches:

| Node | Found from |
| --- | --- |
| **Permission** | APIs that need one (location, camera, microphone, SMS, phone state, accounts, Wi-Fi, Bluetooth, notifications, network, ...); flagged when used but not declared, taking the target SDK and equivalent grants into account |
| **Endpoint** | URL constants, grouped by host (cleartext `http://` flagged), and network clients (HttpURLConnection, OkHttp, Retrofit, WebView, Volley, sockets...) called without a constant URL |
| **Storage** | SQLite, Room, SharedPreferences, DataStore, Realm, SQLCipher, MMKV, files, content providers, Firebase; named by the constant passed (`getSharedPreferences("session")`), with SQL statements as evidence |
| **Native** | `native` methods (as their JNI symbol) and `System.loadLibrary` targets |

Methods that lead to none of these are left out. Exported components are
flagged, except the launcher activity.

The **Overview** level shows each component with everything it can reach,
however deep. **Classes** and **Methods** show the code paths in between.
Kind filters, **Flagged paths** (only what leads to or from a flagged node),
**Find** (Enter for the next match) and **Focus** (a node and its neighbours,
1 to 6 hops) narrow large graphs. Click a node to see its evidence, the call
path from a component to each capability, and what uses it. Double-click
opens the code: a method or class opens its Java (Function, References and
Decompiler follow), a native method or library opens the native listing. MCP
clients get the same data from `behavior_graph`, including the shortest call
path to each capability.

## Comparing versions

Add another version of the app to the project (File > Add APK to Project),
then open **Diff** (or **Compare** in the navigator). Once both APKs are
analysed, the comparison runs on its own, in the background. **Swap** and
**Compare again** redo it. The sections:

| Section | Compares |
| --- | --- |
| **Summary** | everything below in a few lines; a changed signing certificate is called out |
| **Manifest** | package, versions, SDKs, label, `debuggable`, `allowBackup`, signing scheme and certificate, permissions |
| **Components** | added and removed components; changed ones with what changed (exported, intent filter actions and categories) |
| **Classes** | added and removed classes, and classes **renamed** by an obfuscator (the same code under a new name is matched, not reported twice) |
| **Methods** | changed, added and removed methods. Bodies are compared with offsets and branch labels renumbered, so rebuilds do not show up; methods that only use other registers are counted as cosmetic and hidden. Each change says what is new: instructions added and removed, calls and strings that appeared or vanished |
| **Resources** | every resource by type and name: value or configuration count changes |
| **Native libraries** | changed `.so` files with the exported symbols added and removed |
| **Libraries** | bundled libraries added, removed or updated, with versions from `META-INF/*.version` |
| **Endpoints** | URLs that appeared or disappeared |
| **Files** | every archive entry, by CRC and size |

Select a changed method to see it **side by side**: the smali exactly as
compared, or the built-in decompiler's output, with changed lines
highlighted, **Prev change** / **Next change** and the new calls and strings
in a tooltip. Double-click a method to open it in the Analysis panel. MCP
clients use `compare_apks` for the data and `show_diff` to show a change to
the user.

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
