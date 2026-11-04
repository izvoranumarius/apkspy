#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

// Parsed resources.arsc: maps resource ids (0xPPTTEEEE) to their type and
// entry name ("string" / "app_name") and to the value of the default
// configuration (or the first configuration that defines the entry).
//
// Used to turn "@ref/0x7F0E0023" in decoded binary XML into
// "@string/app_name", to resolve the app label, and for the Resources view.
// Bounds-checked throughout: a malformed table yields whatever parsed.
class ResourceTable {
public:
    struct Item {
        uint32_t id = 0;
        std::string type;   // "string", "layout", "drawable", ...
        std::string name;   // entry key
        std::string value;  // rendered default value ("" for complex entries)
        bool complex = false;  // style / array / plurals (map entries)
        int configs = 0;       // number of configurations defining it
    };

    static std::shared_ptr<const ResourceTable> parse(const std::vector<uint8_t>& data, std::string& error);

    const std::string& packageName() const { return package_; }
    size_t size() const { return entries_.size(); }

    // "@string/app_name" (with "android:" prefix for framework ids we know
    // nothing about we return ""); empty when unknown.
    std::string reference(uint32_t id) const;
    // Rendered value of the default configuration, following references up
    // to a few levels ("@string/a" -> "Text"). Empty when unknown/complex.
    std::string value(uint32_t id) const;
    bool lookup(uint32_t id, Item& out) const;
    // Entries filtered by type (exact, "" = all) and name/value substring.
    std::vector<Item> list(const std::string& type, const std::string& filter, size_t limit) const;
    // Distinct type names in id order.
    std::vector<std::string> types() const;
    // Finds the id of "type/name" (or "@type/name"), 0 when absent.
    uint32_t find(const std::string& typeSlashName) const;

private:
    struct Entry {
        uint32_t key = 0;       // index into keys_
        uint8_t typeIndex = 0;  // into typeNames_ (per package type id - 1)
        uint8_t dataType = 0;   // Res_value type (0 = none / complex)
        bool complex = false;
        bool defaultConfig = false;
        uint16_t configs = 0;
        uint32_t data = 0;
    };
    std::string render(uint8_t dataType, uint32_t data, int depth) const;

    std::string package_;
    std::vector<std::string> strings_;    // global value pool
    std::vector<std::string> typeNames_;  // per type id - 1
    std::vector<std::string> keys_;       // entry key pool
    std::unordered_map<uint32_t, Entry> entries_;
};
