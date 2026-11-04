#include <cstdio>
#include <exception>
#include "app/Application.hpp"
#include "app/HeadlessMcp.hpp"

int main(int argc, char** argv) {
    // Headless MCP server mode: no window, protocol on stdin/stdout.
    const std::vector<std::string> args = commandLineArgs(argc, argv);
    for (const std::string& a : args)
        if (a == "--mcp") return runHeadlessMcp(args);
    try {
        Application app;
        return app.run();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "%s\n", e.what());
        return 1;
    }
}
