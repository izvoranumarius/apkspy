#pragma once
#include <string>
#include <vector>

// `apkspy --mcp ...`: runs the MCP server over stdio without a window.
// The client (Claude Code, Claude Desktop, any MCP host) launches ApkSpy as a
// subprocess; the project / APKs given on the command line are opened with
// the same Workspace the GUI uses (jadx decompilation included unless
// --no-decompile is passed). Diagnostics go to stderr - stdout carries
// protocol messages only.
int runHeadlessMcp(const std::vector<std::string>& args);

// UTF-8 command line arguments (wide-char aware on Windows).
std::vector<std::string> commandLineArgs(int argc, char** argv);
