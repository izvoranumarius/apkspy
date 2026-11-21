#include <cstdio>
#include <exception>
#include "app/Application.hpp"
#include "app/HeadlessMcp.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <dbghelp.h>
#include <string>
#include "core/Paths.hpp"
#pragma comment(lib, "dbghelp.lib")

namespace {

// Unhandled crash: writes the exception and a symbolized stack (function,
// file:line from ApkSpy.pdb next to the exe) to <config dir>/crash.log, so
// a crash report carries more than "it closed".
LONG WINAPI writeCrashLog(EXCEPTION_POINTERS* ep) {
    static volatile LONG entered = 0;
    if (InterlockedExchange(&entered, 1)) return EXCEPTION_CONTINUE_SEARCH;
    const std::wstring path = (pathutil::configDir() / "crash.log").wstring();
    FILE* f = _wfopen(path.c_str(), L"w");
    if (!f) return EXCEPTION_CONTINUE_SEARCH;
    const EXCEPTION_RECORD* rec = ep->ExceptionRecord;
    std::fprintf(f, "ApkSpy crashed: exception 0x%08lX at %p\n", rec->ExceptionCode, rec->ExceptionAddress);
    if (rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && rec->NumberParameters >= 2)
        std::fprintf(f, "%s address %p\n", rec->ExceptionInformation[0] ? "writing" : "reading",
                     reinterpret_cast<void*>(rec->ExceptionInformation[1]));
    HANDLE process = GetCurrentProcess(), thread = GetCurrentThread();
    SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
    SymInitialize(process, nullptr, TRUE);
    CONTEXT ctx = *ep->ContextRecord;
    STACKFRAME64 frame{};
    frame.AddrPC.Offset = ctx.Rip;
    frame.AddrFrame.Offset = ctx.Rbp;
    frame.AddrStack.Offset = ctx.Rsp;
    frame.AddrPC.Mode = frame.AddrFrame.Mode = frame.AddrStack.Mode = AddrModeFlat;
    alignas(SYMBOL_INFO) char symBuf[sizeof(SYMBOL_INFO) + 512];
    for (int i = 0; i < 64; ++i) {
        if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, process, thread, &frame, &ctx, nullptr, SymFunctionTableAccess64,
                         SymGetModuleBase64, nullptr) ||
            frame.AddrPC.Offset == 0)
            break;
        auto* sym = reinterpret_cast<SYMBOL_INFO*>(symBuf);
        sym->SizeOfStruct = sizeof(SYMBOL_INFO);
        sym->MaxNameLen = 511;
        DWORD64 disp = 0;
        const char* name = SymFromAddr(process, frame.AddrPC.Offset, &disp, sym) ? sym->Name : "?";
        IMAGEHLP_LINE64 line{};
        line.SizeOfStruct = sizeof(line);
        DWORD lineDisp = 0;
        if (SymGetLineFromAddr64(process, frame.AddrPC.Offset, &lineDisp, &line))
            std::fprintf(f, "  #%02d %s  (%s:%lu)\n", i, name, line.FileName, line.LineNumber);
        else
            std::fprintf(f, "  #%02d %s  [%p]\n", i, name, reinterpret_cast<void*>(frame.AddrPC.Offset));
    }
    std::fclose(f);
    return EXCEPTION_CONTINUE_SEARCH;
}

}  // namespace
#endif

int main(int argc, char** argv) {
#ifdef _WIN32
    SetUnhandledExceptionFilter(writeCrashLog);
#endif
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
