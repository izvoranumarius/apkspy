#include "core/Workspace.hpp"
#include <algorithm>
#include <chrono>
#include <filesystem>

namespace fs = std::filesystem;

namespace {
// Merges the current jadx output directory into the tree without ever
// removing nodes, so TreeNode pointers held by open documents and search
// hits stay valid while results stream in.
void mergeDiskTree(TreeNode& node, const fs::path& dir) {
    std::error_code ec;
    for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
        const fs::path& p = it->path();
        std::string fileName = p.filename().string();
        TreeNode* child = node.findChild(fileName);
        if (it->is_directory(ec)) {
            if (!child) {
                child = node.addChild(std::make_unique<TreeNode>(fileName, p.string(), NodeKind::Folder));
                child->sortRecursive();
            }
            if (child->isFolder()) mergeDiskTree(*child, p);
        } else if (!child) {
            node.addChild(std::make_unique<TreeNode>(fileName, p.string(), TreeNode::classify(fileName)));
        }
    }
}

std::unique_ptr<TreeNode> buildDiskTree(const fs::path& dir, const std::string& name) {
    auto node = std::make_unique<TreeNode>(name, dir.string(), NodeKind::Folder);
    mergeDiskTree(*node, dir);
    node->sortRecursive();
    return node;
}

std::string stripQuotes(std::string s) {
    while (!s.empty() && (s.front() == '"' || s.front() == ' ')) s.erase(s.begin());
    while (!s.empty() && (s.back() == '"' || s.back() == ' ')) s.pop_back();
    return s;
}

std::string normalizedPath(const std::string& path) {
    std::error_code ec;
    fs::path p = fs::absolute(fs::path(path)).lexically_normal();
    return ec ? path : p.string();
}
}  // namespace

bool Workspace::addApk(std::string path, std::string group, std::string jadxOutHint) {
    path = stripQuotes(std::move(path));
    std::string normalized = normalizedPath(path);
    if (findApkByPath(normalized)) {
        log("Already in the project: " + normalized);
        return false;
    }
    auto archive = std::make_shared<ApkArchive>();
    if (!archive->open(path)) {
        log("Could not open " + path);
        return false;
    }
    if (group.empty()) group = archive->name();

    auto root = std::make_unique<Root>();
    root->title = group;
    root->kind = Root::Kind::Apk;
    root->apkPath = normalized;
    root->tree = archive->buildTree();
    root->tree->setName(group);  // group the tree by the same name in both panels
    root->source = archive;
    Root* apkRoot = root.get();
    roots_.push_back(std::move(root));
    log("Added " + path + " to the project");

    attachDecompiled(*apkRoot,
                     jadxOutHint.empty() ? (fs::path(fs::temp_directory_path()) / "apkspy" / (group + "_out")).string()
                                         : jadxOutHint);
    applyPendingTabs(Root::Kind::Apk, group);
    return true;
}

void Workspace::attachDecompiled(Root& apkRoot, const std::string& outDir) {
    auto root = std::make_unique<Root>();
    root->title = apkRoot.title;
    root->kind = Root::Kind::Decompiled;
    root->outDir = outDir;
    root->source = std::make_shared<DiskSource>();
    std::error_code ec;
    if (fs::is_directory(sourcesDir(outDir), ec)) {
        // Results saved by a previous session still exist - attach them
        // without running jadx again.
        root->tree = buildDiskTree(sourcesDir(outDir), apkRoot.title);
        roots_.push_back(std::move(root));
        log("Reattached decompiled results of " + apkRoot.title);
        applyPendingTabs(Root::Kind::Decompiled, apkRoot.title);
    } else {
        // Empty group until jadx produces the sources; keep it browsable
        // while the results stream in.
        root->tree = std::make_unique<TreeNode>(apkRoot.title, "", NodeKind::Folder);
        roots_.push_back(std::move(root));
        jadxQueue_.push_back(apkRoot.title);
    }
}

bool Workspace::removeApk(Root* apkRoot) {
    if (!apkRoot || apkRoot->kind != Root::Kind::Apk) return false;
    const std::string group = apkRoot->title;
    if (jadxActiveGroup_ == group && jadx_.state() == JadxRunner::State::Running) {
        log("Cannot remove " + group + " while it is being decompiled");
        return false;
    }
    jadxQueue_.erase(std::remove(jadxQueue_.begin(), jadxQueue_.end(), group), jadxQueue_.end());
    if (jadxActiveGroup_ == group) jadxActiveGroup_.clear();
    search_.stop();  // hits may reference nodes of the removed trees
    documents_.erase(std::remove_if(documents_.begin(), documents_.end(),
                                    [&](const std::unique_ptr<Document>& d) { return d->rootGroup() == group; }),
                     documents_.end());
    pendingFocus_ = nullptr;
    pendingTabs_.erase(std::remove_if(pendingTabs_.begin(), pendingTabs_.end(),
                                      [&](const PendingTab& t) { return t.group == group; }),
                       pendingTabs_.end());
    roots_.erase(std::remove_if(roots_.begin(), roots_.end(),
                                [&](const std::unique_ptr<Root>& r) { return r->title == group; }),
                 roots_.end());
    log("Removed " + group + " from the project");
    return true;
}

Root* Workspace::findApkByPath(const std::string& path) const {
    std::string normalized = normalizedPath(path);
    for (auto& root : roots_)
        if (root->kind == Root::Kind::Apk && root->apkPath == normalized) return root.get();
    return nullptr;
}

std::vector<Root*> Workspace::apkRoots() const {
    std::vector<Root*> out;
    for (const auto& root : roots_)
        if (root->kind == Root::Kind::Apk) out.push_back(root.get());
    return out;
}

std::vector<Root*> Workspace::decompiledRoots() const {
    std::vector<Root*> out;
    for (const auto& root : roots_)
        if (root->kind == Root::Kind::Decompiled) out.push_back(root.get());
    return out;
}

Root* Workspace::rootByGroup(const std::string& group, Root::Kind kind) const {
    Root* first = nullptr;
    for (const auto& root : roots_) {
        if (root->kind != kind) continue;
        if (!first) first = root.get();
        if (!group.empty() && root->title == group) return root.get();
    }
    return first;
}

void Workspace::startNextJadx() {
    if (jadx_.state() == JadxRunner::State::Running) return;
    while (!jadxQueue_.empty()) {
        std::string group = jadxQueue_.front();
        jadxQueue_.erase(jadxQueue_.begin());
        Root* apk = rootByGroup(group, Root::Kind::Apk);
        Root* dec = rootByGroup(group, Root::Kind::Decompiled);
        if (!apk || !dec) continue;  // removed from the project meanwhile
        std::error_code ec;
        fs::remove_all(dec->outDir, ec);
        fs::create_directories(dec->outDir, ec);
        if (jadx_.start(jadxPath_, apk->apkPath, dec->outDir, jadxArgs_)) {
            jadxActiveGroup_ = group;
            log("Running jadx on " + apk->apkPath + "...");
            return;
        }
        log("Could not start jadx for " + apk->apkPath);
    }
}

void Workspace::update() {
    for (auto& line : jadx_.drainLog()) log_.push_back(std::move(line));
    if (log_.size() > 6000) log_.erase(log_.begin(), log_.begin() + 1000);

    JadxRunner::State s = jadx_.state();
    if (s == JadxRunner::State::Running) {
        // While jadx runs, keep merging its output into the Decompiled tree
        // so partially generated results can be browsed right away.
        if (!jadxActiveGroup_.empty()) {
            auto now = std::chrono::steady_clock::now();
            float elapsed = std::chrono::duration<float>(now - lastTreeRefresh_).count();
            if (elapsed > 1.5f) {
                lastTreeRefresh_ = now;
                refreshDecompiledTree();
            }
        }
        return;
    }

    if (!jadxActiveGroup_.empty()) {
        std::string group = std::move(jadxActiveGroup_);
        jadxActiveGroup_.clear();
        if (s == JadxRunner::State::Done) {
            refreshDecompiledTree();
            decompileSwitch_ = true;
            log("Decompilation of " + group + " finished");
        } else if (s == JadxRunner::State::Failed) {
            decompileFailure_ = true;
            log("Decompilation of " + group + " failed. Check the jadx path in File > Settings > JADX");
        }
    }
    startNextJadx();
}

bool Workspace::takeDecompileSwitch() {
    bool v = decompileSwitch_;
    decompileSwitch_ = false;
    return v;
}

bool Workspace::takeDecompileFailure() {
    bool v = decompileFailure_;
    decompileFailure_ = false;
    return v;
}

std::string Workspace::sourcesDir(const std::string& outDir) {
    return (fs::path(outDir) / "sources").string();
}

void Workspace::refreshDecompiledTree() {
    if (jadxActiveGroup_.empty()) return;
    Root* dec = rootByGroup(jadxActiveGroup_, Root::Kind::Decompiled);
    if (!dec) return;
    std::error_code ec;
    if (!fs::is_directory(sourcesDir(dec->outDir), ec)) return;
    mergeDiskTree(*dec->tree, sourcesDir(dec->outDir));
    dec->tree->sortRecursive();
}

Document* Workspace::findDocument(const TreeNode& node) {
    for (auto& d : documents_)
        if (d->node() == &node) return d.get();
    return nullptr;
}

void Workspace::openNode(Root& root, const TreeNode& node, int line, OpenMode mode) {
    if (node.isFolder()) return;
    Document* existing = findDocument(node);
    if (existing) {
        if (mode == OpenMode::Permanent) existing->promote();
        if (line >= 0) existing->goTo(line);
        pendingFocus_ = existing;
        return;
    }
    std::vector<uint8_t> bytes;
    if (!root.source->read(node, bytes)) {
        log("Failed to read " + node.name());
        return;
    }
    // Replacing the previous preview tab: if it was edited, keep it as a
    // permanent tab so nothing is lost; otherwise drop it.
    for (auto it = documents_.begin(); it != documents_.end(); ++it) {
        if ((*it)->isPreview()) {
            if ((*it)->isDirty()) {
                (*it)->promote();
            } else {
                if (pendingFocus_ == it->get()) pendingFocus_ = nullptr;
                documents_.erase(it);
            }
            break;
        }
    }
    auto doc = std::make_unique<Document>(node.name(), &node, std::move(bytes), root.kind == Root::Kind::Decompiled);
    doc->setRootKind(root.kind == Root::Kind::Decompiled ? 1 : 0);
    doc->setRootGroup(root.title);
    if (mode == OpenMode::Preview) doc->setPreview(true);
    if (line >= 0) doc->goTo(line);
    pendingFocus_ = doc.get();
    documents_.push_back(std::move(doc));
}

void Workspace::openByPath(int rootKind, const std::string& group, const std::string& path, OpenMode mode) {
    Root* root = rootByGroup(group, rootKind == 1 ? Root::Kind::Decompiled : Root::Kind::Apk);
    if (!root || !root->tree) return;
    TreeNode* node = root->tree->findByPath(path);
    if (!node || node->isFolder()) return;
    openNode(*root, *node, -1, mode);
}

void Workspace::promoteDocument(Document* doc) {
    if (doc) doc->promote();
}

void Workspace::closeDocument(const Document* doc) {
    if (pendingFocus_ == doc) pendingFocus_ = nullptr;
    for (auto it = documents_.begin(); it != documents_.end(); ++it) {
        if (it->get() == doc) {
            documents_.erase(it);
            return;
        }
    }
}

void Workspace::closeAllDocuments() {
    pendingFocus_ = nullptr;
    documents_.clear();
}

void Workspace::closeAll() {
    search_.stop();
    documents_.clear();
    roots_.clear();
    pendingFocus_ = nullptr;
    pendingTabs_.clear();
    jadxQueue_.clear();
    // An active jadx run is left alone: its output directory is orphaned and
    // its completion is ignored (jadxActiveGroup_ was cleared with the
    // roots), so a new project can be used while it winds down.
    jadxActiveGroup_.clear();
}

Document* Workspace::takeFocusRequest() {
    Document* d = pendingFocus_;
    pendingFocus_ = nullptr;
    return d;
}

void Workspace::log(std::string message) { log_.push_back(std::move(message)); }

void Workspace::applyPendingTabs(Root::Kind kind, const std::string& group) {
    if (pendingTabs_.empty()) return;
    int wanted = kind == Root::Kind::Decompiled ? 1 : 0;
    for (const PendingTab& tab : pendingTabs_) {
        if (tab.rootKind != wanted) continue;
        if (!tab.group.empty() && tab.group != group) continue;
        openByPath(wanted, tab.group, tab.path, OpenMode::Permanent);
    }
    pendingTabs_.erase(std::remove_if(pendingTabs_.begin(), pendingTabs_.end(),
                                      [&](const PendingTab& t) {
                                          return t.rootKind == wanted &&
                                                 (t.group.empty() || t.group == group);
                                      }),
                       pendingTabs_.end());
}
