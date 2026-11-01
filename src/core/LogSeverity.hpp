#pragma once
#include <cctype>
#include <string>
#include <string_view>

// One severity classifier for every log line in the app (jadx output and
// ApkSpy's own messages). jadx prints lines like "INFO  - loading ...",
// "WARN  - ..." and "ERROR - ..."; the classifier looks for WARN/ERROR as a
// standalone token followed by the jadx separator, so class names such as
// "ErrorHandler" no longer count as errors.
enum class LogSeverity { Info, Warn, Error };

namespace logsev {

inline LogSeverity classify(std::string_view line) {
    auto isWord = [](char c) {
        unsigned char u = (unsigned char)c;
        return std::isalnum(u) || c == '_';
    };
    for (std::string_view word : {"ERROR", "Error", "error"}) {
        size_t pos = 0;
        while ((pos = line.find(word, pos)) != std::string_view::npos) {
            bool leftOk = pos == 0 || !isWord(line[pos - 1]);
            size_t after = pos + word.size();
            bool rightIsWord = after < line.size() && isWord(line[after]);
            if (leftOk && !rightIsWord) {
                // "error:" / "ERROR -" / "error]" style markers count; a bare
                // "Error" token inside a sentence (e.g. a message) does too,
                // which matches the previous behaviour of both consumers.
                return LogSeverity::Error;
            }
            pos = after;
        }
    }
    for (std::string_view word : {"WARN", "Warn", "warning:"}) {
        size_t pos = 0;
        while ((pos = line.find(word, pos)) != std::string_view::npos) {
            bool leftOk = pos == 0 || !isWord(line[pos - 1]);
            size_t after = pos + word.size();
            bool rightIsWord = after < line.size() && isWord(line[after]);
            if (leftOk && !rightIsWord) return LogSeverity::Warn;
            pos = after;
        }
    }
    return LogSeverity::Info;
}

}  // namespace logsev
