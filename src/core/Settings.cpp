#include "core/Settings.hpp"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

namespace {
std::string trimCr(std::string s) {
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n')) s.pop_back();
    return s;
}
}

void Settings::load(const std::string& path) {
    std::ifstream in(path);
    if (!in) return;
    std::string line;
    while (std::getline(in, line)) {
        line = trimCr(std::move(line));  // tolerate CRLF files everywhere
        if (line.empty() || line.front() == '#') continue;
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        map_[trimCr(line.substr(0, eq))] = line.substr(eq + 1);
    }
}

bool Settings::save(const std::string& path) const {
    // Atomic write: a crash mid-save can never truncate the previous file.
    const std::string tmp = path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary);
        if (!out) return false;
        out << "# ApkSpy settings - safe to delete, defaults will be used\n";
        // Sorted so consecutive saves produce readable, minimal diffs.
        std::vector<const std::string*> keys;
        keys.reserve(map_.size());
        for (const auto& [key, value] : map_) keys.push_back(&key);
        std::sort(keys.begin(), keys.end(),
                  [](const std::string* a, const std::string* b) { return *a < *b; });
        for (const std::string* key : keys) out << *key << '=' << map_.at(*key) << '\n';
        out.flush();
        if (!out) return false;
    }
    std::remove(path.c_str());  // rename() won't overwrite on Windows
    return std::rename(tmp.c_str(), path.c_str()) == 0;
}

std::string Settings::getString(const std::string& key, const std::string& fallback) const {
    auto it = map_.find(key);
    return it == map_.end() ? fallback : it->second;
}

int Settings::getInt(const std::string& key, int fallback) const {
    auto it = map_.find(key);
    if (it == map_.end()) return fallback;
    return std::atoi(it->second.c_str());
}

bool Settings::getBool(const std::string& key, bool fallback) const {
    auto it = map_.find(key);
    if (it == map_.end()) return fallback;
    const std::string& v = it->second;
    return v == "1" || v == "true" || v == "yes" || v == "on";
}

void Settings::set(const std::string& key, std::string value) { map_[key] = std::move(value); }
void Settings::set(const std::string& key, const char* value) { map_[key] = value; }
void Settings::set(const std::string& key, int value) { map_[key] = std::to_string(value); }
void Settings::set(const std::string& key, bool value) { map_[key] = value ? "1" : "0"; }
