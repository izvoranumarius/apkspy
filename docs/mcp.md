# MCP server

ApkSpy exposes the open project to AI assistants through the
[Model Context Protocol](https://modelcontextprotocol.io). There are two ways to run it.

## From the running app

Open **File > Settings > AI (MCP)** and press
**Start**. The endpoint listens on
`http://127.0.0.1:<port>/mcp` (loopback only, default port 8765) and by
default requires a bearer token; the page's buttons copy ready-to-paste client
configuration, e.g. for Claude Code:

```
claude mcp add --transport http apkspy http://127.0.0.1:8765/mcp --header "Authorization: Bearer <token>"
```

In this mode the assistant sees exactly what you see and can open files in
your editor (`open_in_editor`).

## Headless (stdio)

The client launches ApkSpy itself, with no window:

```
ApkSpy --mcp --project path/to/project.apkspy
ApkSpy --mcp --apk app.apk [--apk other.apk] [--analyze] [--no-decompile] [--no-devices]
```

## Tools

All tools have JSON-schema validated input and structured output:
`list_apks`, `apk_info` (package, versions, SDKs, flags, permissions,
components, signatures), `get_manifest`, `list_files`, `read_file`,
`hexdump`, `search_code`, `decompile_class`, `run_analysis` (long-running,
progress + cancellation), `dex_info`, `list_classes`, `get_class`,
`get_method` (smali, callees, constant arguments), `decompile_method`
(built-in Java-like decompiler), `xrefs`, `call_graph`,
`control_flow_graph` (JSON or DOT), `class_hierarchy`, `search_strings`,
`find_endpoints`, `list_resources`, `resolve_resource`, `list_native_libs`,
`inspect_native_lib`, `native_functions`, `disassemble_native`,
`decompile_native` (built-in C-like decompiler; both list the variables
with their types), `rename_variable` (IDA-style variable names and types,
shared with the Decompiler panel; listed by `list_annotations` with kind
`rename` / `type`),
`native_xrefs`, `native_strings`, `compare_apks`, the GUI-only
`open_in_editor`, `show_native` and `show_panel`, the device tools
`device_list`, `device_info`, `device_processes`, `logcat_read`,
`process_stats`, `process_threads`, `process_backtrace`, `debugger_state`,
`debugger_attach`, `debugger_control`, `debugger_select`,
`debugger_breakpoint` (line and exception breakpoints),
`debugger_inspect` (object fields / array elements), the traffic tools
`traffic_status`, `traffic_control`, `traffic_list`, `traffic_get`,
`traffic_endpoints`, and `list_annotations`, `add_annotation`,
`remove_annotation`, plus `native_cfg` and the GUI-only `show_method`. That is
54 tools in total, 50 headless. The headless server saves
annotation changes to the project file on exit; started without a project
file, it has nowhere to keep them.

## Design and safety

- Tool handlers run on the thread that owns the project (the UI thread, or
  the main loop in headless mode), one at a time - concurrent requests can
  never observe or corrupt half-updated state. Expensive work (searching,
  analysis queries, adb calls) runs afterwards on the request's own thread
  using immutable snapshots, so the UI never stalls.
- Long-running calls honour `notifications/cancelled`, report progress over
  stdio, and are cancelled when the server stops.
- Files are only reachable through the project trees (no raw filesystem
  paths); there is no tool that executes arbitrary commands. Results are
  size-capped and paginated (`offset` / `limit`).
- The HTTP endpoint binds 127.0.0.1 only, rejects requests whose `Origin`
  is not local (DNS-rebinding protection) and compares the bearer token in
  constant time.
