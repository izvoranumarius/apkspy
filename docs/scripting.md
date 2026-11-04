# Scripting

The **Scripts** workspace edits and runs Python scripts (`F5`) against the open
project. The editor has syntax colouring and line numbers, and output goes to
the Output panel below it (filter it to `[scripts]` to see only that).

Each MCP tool is a function of the `apkspy` module, with the tool's arguments
and structured results:

```python
import apkspy

apkspy.run_analysis()
for c in apkspy.list_classes(filter="login")["classes"]:
    print(c)

# Open a function's graph for yourself, then leave a comment on it.
apkspy.show_native(path="lib/arm64-v8a/libfoo.so", target="Java_com_foo_check", view="graph")
apkspy.add_annotation(kind="comment", path="lib/arm64-v8a/libfoo.so", address="0x1234", text="license check")
```

`apkspy.tools()` lists every tool, failures raise `apkspy.ApkSpyError`, and a
trailing underscore passes a Python keyword (`get_class(class_="com.a.B")`).
Scripts save as you type and use your installed Python, so any of its packages
work; set its path under File > Settings > Scripts when `python` is not on `PATH`. They run with your user's full
rights, so only run scripts you trust. Files live in the `scripts` folder of
the ApkSpy config directory. ApkSpy reaches them through a private local
endpoint with a fresh token, whatever the MCP server setting.
