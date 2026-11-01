#pragma once
#include <algorithm>
#include <memory>
#include <string>
#include <vector>
#include "core/TextUtils.hpp"

enum class NodeKind {
    Folder, Java, Kotlin, Xml, Json, Smali, Groovy, Yaml, Web,
    Text, Image, Dex, Native, Binary
};

class TreeNode {
public:
    TreeNode(std::string name, std::string path, NodeKind kind)
        : name_(std::move(name)), path_(std::move(path)), kind_(kind) {}

    const std::string& name() const { return name_; }
    const std::string& path() const { return path_; }
    // Renames the node (used to give multi-APK tree roots their unique group
    // name without rebuilding the tree).
    void setName(std::string name) { name_ = std::move(name); }
    NodeKind kind() const { return kind_; }
    bool isFolder() const { return kind_ == NodeKind::Folder; }
    const std::vector<std::unique_ptr<TreeNode>>& children() const { return children_; }

    TreeNode* findChild(const std::string& name) const {
        for (const auto& c : children_)
            if (c->name_ == name) return c.get();
        return nullptr;
    }

    TreeNode* addChild(std::unique_ptr<TreeNode> node) {
        children_.push_back(std::move(node));
        return children_.back().get();
    }

    // Looks a node up by the exact path string stored in its nodes
    // (zip entry path for APK roots, absolute disk path for decompiled
    // roots). Used to restore editor tabs between sessions.
    TreeNode* findByPath(const std::string& path) {
        if (path_ == path && !path.empty()) return this;
        for (const auto& c : children_)
            if (TreeNode* hit = c->findByPath(path)) return hit;
        return nullptr;
    }

    void sortRecursive() {
        std::stable_sort(children_.begin(), children_.end(),
                         [](const std::unique_ptr<TreeNode>& a, const std::unique_ptr<TreeNode>& b) {
                             if (a->isFolder() != b->isFolder()) return a->isFolder();
                             return a->name_ < b->name_;
                         });
        for (auto& c : children_) c->sortRecursive();
    }

    static NodeKind classify(const std::string& fileName) {
        // Common extension-less text files
        static const char* kTextNames[] = {"LICENSE", "LICENSE.txt", "NOTICE", "README",
                                           "CHANGELOG", "AUTHORS", "CONTRIBUTING",
                                           "Makefile", "Dockerfile"};
        for (const char* n : kTextNames)
            if (fileName == n) return NodeKind::Text;
        size_t dot = fileName.find_last_of('.');
        if (dot == std::string::npos) return NodeKind::Binary;
        std::string ext = tex::asciiLower(fileName.substr(dot + 1));
        if (ext == "java") return NodeKind::Java;
        if (ext == "kt" || ext == "kts") return NodeKind::Kotlin;
        if (ext == "xml") return NodeKind::Xml;
        if (ext == "json") return NodeKind::Json;
        if (ext == "smali") return NodeKind::Smali;
        if (ext == "gradle" || ext == "groovy") return NodeKind::Groovy;
        if (ext == "yml" || ext == "yaml") return NodeKind::Yaml;
        if (ext == "html" || ext == "htm" || ext == "js" || ext == "mjs" || ext == "css") return NodeKind::Web;
        if (ext == "txt" || ext == "properties" || ext == "md" ||
            ext == "mf" || ext == "sf" || ext == "version" || ext == "cfg" || ext == "ini" ||
            // more text formats commonly shipped inside APKs and projects
            ext == "pro" || ext == "sh" || ext == "bat" || ext == "cmd" ||
            ext == "py" || ext == "c" || ext == "h" || ext == "cc" || ext == "cpp" ||
            ext == "cxx" || ext == "hpp" || ext == "hxx" || ext == "m" || ext == "mm" ||
            ext == "aidl" || ext == "scala" || ext == "go" || ext == "rs" ||
            ext == "rb" || ext == "pl" || ext == "lua" || ext == "php" ||
            ext == "toml" || ext == "csv" || ext == "tsv" || ext == "log" ||
            ext == "sql" || ext == "conf" || ext == "list" || ext == "prop")
            return NodeKind::Text;
        if (ext == "png" || ext == "jpg" || ext == "jpeg" || ext == "jpe" || ext == "gif" || ext == "webp" ||
            ext == "bmp" || ext == "tga" || ext == "psd" || ext == "hdr" || ext == "pic" || ext == "ppm" ||
            ext == "pgm" || ext == "pnm")
            return NodeKind::Image;
        if (ext == "dex") return NodeKind::Dex;
        if (ext == "so") return NodeKind::Native;
        return NodeKind::Binary;
    }

private:
    std::string name_;
    std::string path_;
    NodeKind kind_;
    std::vector<std::unique_ptr<TreeNode>> children_;
};
