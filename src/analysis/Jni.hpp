#pragma once
#include <cstdio>
#include <string>
#include <string_view>

// JNI symbol names (JNI spec, "Resolving Native Method Names"): the short
// name a native library exports for a Java `native` method, e.g.
// Lcom/foo/Bar;->baz  ->  Java_com_foo_Bar_baz.
namespace jni {

// Mangles one component: '/' separates packages, '_' -> _1, ';' -> _2,
// '[' -> _3, anything outside [A-Za-z0-9] -> _0xxxx (UTF-16 code unit).
inline std::string mangle(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        const auto c = static_cast<unsigned char>(s[i]);
        if (c == '/' || c == '.') out += '_';
        else if (c == '_') out += "_1";
        else if (c == ';') out += "_2";
        else if (c == '[') out += "_3";
        else if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) out += static_cast<char>(c);
        else {
            // Decode one UTF-8 sequence (BMP only; anything else is escaped byte-wise).
            unsigned code = c;
            if ((c & 0xE0) == 0xC0 && i + 1 < s.size()) {
                code = ((c & 0x1Fu) << 6) | (static_cast<unsigned char>(s[i + 1]) & 0x3Fu);
                i += 1;
            } else if ((c & 0xF0) == 0xE0 && i + 2 < s.size()) {
                code = ((c & 0x0Fu) << 12) | ((static_cast<unsigned char>(s[i + 1]) & 0x3Fu) << 6) |
                       (static_cast<unsigned char>(s[i + 2]) & 0x3Fu);
                i += 2;
            }
            char buf[8];
            std::snprintf(buf, sizeof buf, "_0%04x", code & 0xFFFFu);
            out += buf;
        }
    }
    return out;
}

// "Lcom/foo/Bar;" + "baz" -> "Java_com_foo_Bar_baz".
inline std::string shortName(std::string_view classDescriptor, std::string_view method) {
    std::string_view cls = classDescriptor;
    if (cls.size() >= 2 && cls.front() == 'L' && cls.back() == ';') cls = cls.substr(1, cls.size() - 2);
    return "Java_" + mangle(cls) + "_" + mangle(method);
}

// Overloaded natives also export the long form: short name + "__" + mangled argument descriptors.
inline std::string longName(std::string_view classDescriptor, std::string_view method, std::string_view proto) {
    const size_t open = proto.find('('), close = proto.find(')');
    const std::string_view args = open != std::string_view::npos && close != std::string_view::npos && close > open
                                      ? proto.substr(open + 1, close - open - 1)
                                      : std::string_view();
    return shortName(classDescriptor, method) + "__" + mangle(args);
}

}  // namespace jni
