#include "core/Settings.hpp"
#include <cstdlib>
#include <fstream>

void Settings::load(const std::string& path) {
    std::ifstream in(path);
    if (!in) return;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line.front() == '#') continue;
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        map_[line.substr(0, eq)] = line.substr(eq + 1);
    }
}

bool Settings::save(const std::string& path) const {
    std::ofstream out(path);
    if (!out) return false;
    out << "# ApkSpy user settings\n";
    for (const auto& [key, value] : map_) out << key << '=' << value << '\n';
    return true;
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
