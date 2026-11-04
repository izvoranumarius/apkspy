# ApkSpy

An Android reverse-engineering IDE in C++. Open an APK, read its code, trace it
through bytecode and native libraries, and debug it live on a device.

## Features

- **Decompiled code**: browse, search and edit [jadx](https://github.com/skylot/jadx)
  output and the original APK in tabs.
- **Bytecode analysis**: smali, cross-references, call graphs, control-flow
  graphs and string extraction, with no jadx needed.
- **Native libraries**: ELF details, an AArch64 disassembler and function graphs.
- **Live debugging**: attach to a debuggable app over JDWP, with breakpoints,
  stepping and object inspection, plus Logcat and a process monitor.
- **Traffic capture**: map an app's HTTP API from a device or emulator.
- **Python scripting** and an **MCP server** for AI assistants.
- **APK comparison**: see what changed between two versions.

## Get started

Download the Windows build from
[Releases](https://github.com/izvoranumarius/apkspy/releases), unzip it and run
`ApkSpy.exe`. Drop an APK on the window to start.

Decompiling needs jadx, device features need adb, and scripts need Python.
[Getting started](docs/getting-started.md) covers setup.

To build from source:

- **Windows**: open `ApkSpy.sln` in Visual Studio 2022, select x64 and press F5.
- **Linux and macOS**: install GLFW 3 and pkg-config, then run `make`.

## Documentation

- [Getting started](docs/getting-started.md): setup, projects, workspaces, shortcuts
- [Browsing code](docs/browsing-code.md): Explorer, editor, search, bookmarks, hex viewer
- [Analysis](docs/analysis.md): bytecode, native code, graphs, resources, comparing APKs
- [Debugging and network](docs/debugging.md): devices, Logcat, debugger, traffic
- [Scripting](docs/scripting.md): the `apkspy` Python module
- [MCP server](docs/mcp.md): connect AI assistants
- [Development](docs/development.md): building, tests, source layout
- [Changelog](CHANGES.md)

Only analyse apps you are allowed to.
