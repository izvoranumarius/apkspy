#include "core/Workspace.hpp"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <unordered_map>

#include "core/AxmlDecoder.hpp"
#include "core/Paths.hpp"
#include "core/SafePath.hpp"
#include "core/TextUtils.hpp"

namespace fs = std::filesystem;

namespace {

// ---- jadx output directory ownership ---------------------------------------
// Every directory ApkSpy creates for jadx output carries this marker file.
// Only directories with a valid marker are ever deleted recursively, so a
// project file (or anything else) can never make ApkSpy wipe an arbitrary
// path. The status line records whether a jadx run finished cleanly;
// partial output from a killed or crashed run is never re-attached.
constexpr const char* kOutMarkerName = ".apkspy_out";
constexpr const char* kOutMarkerMagic = "apkspy-out-v1";

std::string markerStatus(const fs::path& dir, bool& valid) {
    valid = false;
    std::error_code ec;
    if (!fs::is_directory(dir, ec)) return {};
    std::FILE* f =
        std::fopen(pathutil::toUtf8(dir / kOutMarkerName).c_str(), "rb");
    if (!f) return {};
    std::string content;
    char buf[128];
    size_t got = std::fread(buf, 1, sizeof buf - 1, f);
    std::fclose(f);
    buf[got] = 0;
    content.assign(buf, got);
    while (!content.empty() && (content.back() == '\n' || content.back() == '\r')) content.pop_back();
    size_t nl = content.find('\n');
    std::string first = nl == std::string::npos ? content : content.substr(0, nl);
    if (first != kOutMarkerMagic) return {};
    valid = true;
    return nl == std::string::npos ? std::string() : content.substr(nl + 1);
}

void writeMarker(const fs::path& dir, const char* status) {
    std::error_code ec;
    fs::create_directories(dir, ec);
    std::FILE* f =
        std::fopen(pathutil::toUtf8(dir / kOutMarkerName).c_str(), "wb");
    if (!f) return;
    std::fprintf(f, "%s\n%s\n", kOutMarkerMagic, status);
    std::fclose(f);
}

bool removeOutDirIfOwned(const fs::path& dir) {
    bool valid = false;
    markerStatus(dir, valid);
    if (!valid) return false;  // not ours (or no marker): never delete
    std::error_code ec;
    fs::remove_all(dir, ec);
    return !ec;
}

// 64-bit FNV-1a; only used to derive a unique directory name.
uint64_t fnv1a(const std::string& s) {
    uint64_t h = 1469598103934665603ull;
    for (unsigned char c : s) {
        h ^= c;
        h *= 1099511628211ull;
    }
    return h;
}

// Merges the current jadx output directory into the tree without ever
// removing nodes, so TreeNode pointers held by open documents and search
// hits stay valid while results stream in. Children are indexed per folder
// so wide packages don't degrade into O(n^2) lookups.
void mergeDiskTree(TreeNode& node, const fs::path& dir) {
    std::error_code ec;
    std::unordered_map<std::string, TreeNode*> index;
    index.reserve(node.children().size() * 2 + 8);
    for (const auto& c : node.children()) index.emplace(c->name(), c.get());
    for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
        const fs::path& p = it->path();
        std::string fileName = pathutil::toUtf8(p.filename());
        TreeNode* child = nullptr;
        if (auto found = index.find(fileName); found != index.end()) child = found->second;
        if (it->is_directory(ec)) {
            if (!child) {
                child = node.addChild(std::make_unique<TreeNode>(fileName, pathutil::toUtf8(p), NodeKind::Folder));
                index.emplace(fileName, child);
                child->sortRecursive();
            }
            if (child->isFolder()) mergeDiskTree(*child, p);
        } else if (!child) {
            child = node.addChild(std::make_unique<TreeNode>(fileName, pathutil::toUtf8(p), TreeNode::classify(fileName)));
            index.emplace(fileName, child);
        }
    }
}

std::unique_ptr<TreeNode> buildDiskTree(const fs::path& dir, const std::string& name) {
    auto node = std::make_unique<TreeNode>(name, pathutil::toUtf8(dir), NodeKind::Folder);
    mergeDiskTree(*node, dir);
    node->sortRecursive();
    return node;
}

std::string stripQuotes(std::string s) {
    while (!s.empty() && (s.front() == '"' || s.front() == ' ')) s.erase(s.begin());
    while (!s.empty() && (s.back() == '"' || s.back() == ' ')) s.pop_back();
    return s;
}

}  // namespace

std::string Workspace::jadxCacheRoot() {
    return pathutil::toUtf8(fs::temp_directory_path() / "apkspy");
}

bool Workspace::isOwnedOutDir(const std::string& dir) {
    bool valid = false;
    markerStatus(pathutil::fromUtf8(dir), valid);
    return valid;
}

// Derives a fresh output directory for an APK: the name mixes the APK's file
// name (readability) with a hash of path + size + mtime (uniqueness and
// staleness detection). Directories that already exist but carry no ApkSpy
// marker are never reused or deleted - a numeric suffix is appended instead.
static std::string deriveOutDir(const std::string& apkPath) {
    std::error_code ec;
    fs::path apk = pathutil::fromUtf8(apkPath);
    uint64_t size = fs::file_size(apk, ec);
    if (ec) size = 0;
    uint64_t mtime = 0;
    fs::file_time_type written = fs::last_write_time(apk, ec);
    if (!ec) mtime = (uint64_t)written.time_since_epoch().count();

    std::string seed = apkPath + "|" + std::to_string(size) + "|" + std::to_string(mtime);
    char hash[17];
    std::snprintf(hash, sizeof hash, "%012llx", (unsigned long long)(fnv1a(seed) & 0xFFFFFFFFFFFFull));

    std::string stem = pathutil::toUtf8(apk.stem());
    if (stem.empty()) stem = "apk";
    if (stem.size() > 40) stem.resize(40);
    for (char& c : stem)
        if (c == '/' || c == '\\') c = '_';  // defensive; stems have no separators

    fs::path base = fs::temp_directory_path() / "apkspy";
    fs::path candidate = base / (stem + "_" + hash);
    for (int i = 2; fs::exists(candidate, ec) && i < 64; ++i) {
        bool owned = false;
        markerStatus(candidate, owned);
        if (owned) break;  // ours: reuse (reattach or re-run into it)
        candidate = base / (stem + "_" + hash + "_r" + std::to_string(i));
    }
    return pathutil::toUtf8(candidate);
}

bool Workspace::addApk(std::string path, std::string group) {
    path = stripQuotes(std::move(path));
    std::string normalized = pathutil::normalize(path);
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
    bumpVersion();
    log("Added " + path + " to the project");

    attachDecompiled(*apkRoot, deriveOutDir(normalized));
    applyPendingTabs(Root::Kind::Apk, group);
    return true;
}

void Workspace::attachDecompiled(Root& apkRoot, const std::string& outDir) {
    auto root = std::make_unique<Root>();
    root->title = apkRoot.title;
    root->kind = Root::Kind::Decompiled;
    root->outDir = outDir;
    root->source = std::make_shared<DiskSource>();
    bool owned = false;
    std::string status = markerStatus(pathutil::fromUtf8(outDir), owned);
    std::error_code ec;
    if (owned && status == "done" && fs::is_directory(pathutil::fromUtf8(sourcesDir(outDir)), ec)) {
        // A previous jadx run finished cleanly and its results still exist -
        // attach them without running jadx again.
        root->tree = buildDiskTree(pathutil::fromUtf8(sourcesDir(outDir)), apkRoot.title);
        roots_.push_back(std::move(root));
        bumpVersion();
        ++treeEpochs_[apkRoot.title];
        log("Reattached decompiled results of " + apkRoot.title);
        applyPendingTabs(Root::Kind::Decompiled, apkRoot.title);
        ensureSymbolIndex(apkRoot.title);
    } else {
        // Empty group until jadx produces the sources; keep it browsable
        // while the results stream in.
        root->tree = std::make_unique<TreeNode>(apkRoot.title, "", NodeKind::Folder);
        roots_.push_back(std::move(root));
        bumpVersion();
        jadxQueue_.push_back(apkRoot.title);
    }
}

bool Workspace::removeApk(Root* apkRoot) {
    if (!apkRoot || apkRoot->kind != Root::Kind::Apk) return false;
    const std::string group = apkRoot->title;
    std::string outDir;
    if (const Root* dec = rootByGroup(group, Root::Kind::Decompiled)) outDir = dec->outDir;
    if (jadxActiveGroup_ == group && jadx_.state() == JadxRunner::State::Running) {
        log("Cannot remove " + group + " while it is being decompiled - cancel it first");
        return false;
    }
    jadxQueue_.erase(std::remove(jadxQueue_.begin(), jadxQueue_.end(), group), jadxQueue_.end());
    if (jadxActiveGroup_ == group) jadxActiveGroup_.clear();
    search_.stop();  // hits may reference nodes of the removed trees
    documents_.erase(std::remove_if(documents_.begin(), documents_.end(),
                                    [&](const std::unique_ptr<Document>& d) { return d->rootGroup() == group; }),
                     documents_.end());
    pendingFocus_ = nullptr;
    if (activeDocument_ && activeDocument_->rootGroup() == group) activeDocument_ = nullptr;
    pendingTabs_.erase(std::remove_if(pendingTabs_.begin(), pendingTabs_.end(),
                                      [&](const PendingTab& t) { return t.group == group; }),
                       pendingTabs_.end());
    roots_.erase(std::remove_if(roots_.begin(), roots_.end(),
                                [&](const std::unique_ptr<Root>& r) { return r->title == group; }),
                 roots_.end());
    // Free the decompiled results we own (marker-guarded); anything we did
    // not create stays on disk.
    if (!outDir.empty() && removeOutDirIfOwned(pathutil::fromUtf8(outDir)))
        log("Deleted decompiled results of " + group);
    nav_.purgeGroup(group);  // Back/Forward must not resurrect removed APKs
    symbols_.purgeGroup(group);
    treeEpochs_.erase(group);
    if (export_.busy()) export_.cancel();  // items may point into the removed tree
    bumpVersion();
    log("Removed " + group + " from the project");
    return true;
}

Root* Workspace::findApkByPath(const std::string& path) const {
    std::string normalized = pathutil::normalize(path);
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
        fs::path outDir = pathutil::fromUtf8(dec->outDir);
        // Only ever wipe a directory we created ourselves (marker file).
        removeOutDirIfOwned(outDir);
        std::error_code ec;
        fs::create_directories(outDir, ec);
        writeMarker(outDir, "pending");
        // The tree this search is walking is about to be mutated every 1.5 s.
        if (search_.group() == group) search_.stop();
        if (jadx_.start(jadxPath_, apk->apkPath, dec->outDir, jadxArgs_)) {
            jadxActiveGroup_ = group;
            log("Running jadx on " + apk->apkPath + "...");
            return;
        }
        log("Could not start jadx for " + apk->apkPath);
    }
}

void Workspace::cancelDecompile() {
    jadxQueue_.clear();
    if (jadx_.state() == JadxRunner::State::Running) {
        jadx_.cancel();
        log("Cancelling decompilation...");
    }
}

void Workspace::update() {
    for (auto& line : jadx_.drainLog()) log_.push_back(std::move(line));
    if (log_.size() > 6000) log_.erase(log_.begin(), log_.begin() + 1000);

    // Folder export (M5): one item per frame, on the UI thread - the only
    // thread allowed to read through an APK root's ContentSource.
    if (export_.busy()) {
        export_.pump();
        std::string err = export_.takeLastError();
        if (!err.empty()) log("Export: " + err);
        if (!export_.busy()) {
            if (export_.state() == ExportJob::State::Cancelled)
                log("Export cancelled (" + std::to_string(export_.done()) + " of " +
                    std::to_string(export_.done() + export_.failed()) + " file(s) written)");
            else
                log("Export finished: " + std::to_string(export_.done()) + " file(s), " +
                    std::to_string(export_.failed()) + " failed");
        }
    }

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
        const std::string group = std::move(jadxActiveGroup_);
        jadxActiveGroup_.clear();
        if (s == JadxRunner::State::Done) {
            // Record that these results are complete so a later session can
            // re-attach them without re-running jadx.
            if (const Root* dec = rootByGroup(group, Root::Kind::Decompiled))
                writeMarker(pathutil::fromUtf8(dec->outDir), "done");
            refreshDecompiledTree(group);
            ensureSymbolIndex(group);  // index the finished tree for Ctrl+click
            decompileSwitch_ = true;
            log("Decompilation of " + group + " finished");
        } else if (s == JadxRunner::State::Cancelled) {
            decompileFailure_ = true;
            log("Decompilation of " + group + " was cancelled - partial results were discarded");
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
    return pathutil::toUtf8(pathutil::fromUtf8(outDir) / "sources");
}

void Workspace::refreshDecompiledTree(const std::string& group) {
    const std::string& active = group.empty() ? jadxActiveGroup_ : group;
    if (active.empty()) return;
    Root* dec = rootByGroup(active, Root::Kind::Decompiled);
    if (!dec) return;
    std::error_code ec;
    if (!fs::is_directory(pathutil::fromUtf8(sourcesDir(dec->outDir)), ec)) return;
    mergeDiskTree(*dec->tree, pathutil::fromUtf8(sourcesDir(dec->outDir)));
    dec->tree->sortRecursive();
    ++treeEpochs_[active];  // the symbol index (M3) rebuilds against this epoch
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
                bumpVersion();
            } else {
                if (pendingFocus_ == it->get()) pendingFocus_ = nullptr;
                documents_.erase(it);
                bumpVersion();
            }
            break;
        }
    }
    auto doc = std::make_unique<Document>(
        node.name(), &node, std::move(bytes),
        root.kind == Root::Kind::Decompiled ? RootKind::Decompiled : RootKind::Apk);
    doc->setRootGroup(root.title);
    if (mode == OpenMode::Preview) doc->setPreview(true);
    if (line >= 0) doc->goTo(line);
    pendingFocus_ = doc.get();
    documents_.push_back(std::move(doc));
    bumpVersion();
}

void Workspace::openByPath(RootKind rootKind, const std::string& group, const std::string& path, OpenMode mode) {
    Root* root = rootByGroup(group, rootKind == RootKind::Decompiled ? Root::Kind::Decompiled : Root::Kind::Apk);
    if (!root || !root->tree) return;
    TreeNode* node = root->tree->findByPath(path);
    if (!node || node->isFolder()) return;
    openNode(*root, *node, -1, mode);
}

// ---------------------------------------------------------------------------
// Back/Forward navigation (M2)
// ---------------------------------------------------------------------------

NavLocation Workspace::locationOf(const Document& doc) const {
    NavLocation loc;
    loc.kind = doc.rootKind();
    loc.group = doc.rootGroup();
    loc.path = doc.node() ? doc.node()->path() : std::string();
    // Prefer the live view position; a document that was never drawn yet
    // falls back to its highlight line, then to the top.
    loc.line = doc.viewLine() >= 0 ? doc.viewLine() : std::max(0, doc.highlight());
    return loc;
}

void Workspace::navigateTo(Root& root, const TreeNode& node, int line, const NavLocation* origin) {
    NavLocation dest;
    dest.kind = root.kind == Root::Kind::Decompiled ? RootKind::Decompiled : RootKind::Apk;
    dest.group = root.title;
    dest.path = node.path();
    dest.line = line < 0 ? 0 : line;
    if (!suppressNav_) nav_.navigate(origin, dest);
    openNode(root, node, line, OpenMode::Permanent);
    // openNode applies goTo(line) itself; nothing else to do here.
}

bool Workspace::navStep(bool forward) {
    while (true) {
        const NavLocation* loc = forward ? nav_.forward() : nav_.back();
        if (!loc) return false;
        Root* root = rootByGroup(loc->group, loc->kind);
        const TreeNode* node = root && root->tree ? root->tree->findByPath(loc->path) : nullptr;
        if (!node || node->isFolder()) {
            log("Navigation target no longer exists: " + loc->path);
            continue;  // skip and try the next entry
        }
        // Re-open (a closed tab is fine) but do NOT re-record the jump.
        suppressNav_ = true;
        openNode(*root, *node, -1, OpenMode::Permanent);
        suppressNav_ = false;
        if (Document* d = findDocument(*node)) d->goTo(loc->line);
        return true;
    }
}

bool Workspace::navBack() { return navStep(false); }
bool Workspace::navForward() { return navStep(true); }

// ---------------------------------------------------------------------------
// Symbol index / Ctrl+click navigation (M3)
// ---------------------------------------------------------------------------

uint64_t Workspace::treeEpoch(const std::string& group) const {
    auto it = treeEpochs_.find(group);
    return it == treeEpochs_.end() ? 0 : it->second;
}

// UI-thread tree walk: collects source files worth indexing. Never call for
// a group whose jadx run is still streaming (the tree mutates meanwhile).
void Workspace::collectSymbolFiles(const TreeNode& node, std::vector<SymbolIndex::File>& out) {
    if (node.isFolder()) {
        for (const auto& c : node.children()) collectSymbolFiles(*c, out);
        return;
    }
    if (node.kind() == NodeKind::Java) out.push_back({node.path(), false});
    else if (node.kind() == NodeKind::Kotlin) out.push_back({node.path(), true});
}

void Workspace::ensureSymbolIndex(const std::string& group) {
    Root* dec = rootByGroup(group, Root::Kind::Decompiled);
    if (!dec || !dec->tree || isGroupDecompiling(group)) return;  // never walk a live tree
    std::vector<SymbolIndex::File> files;
    collectSymbolFiles(*dec->tree, files);
    if (files.empty()) return;
    symbols_.ensureIndex(group, treeEpoch(group), std::move(files), dec->source);
}

bool Workspace::openSymbol(const std::string& group, const std::string& identifier, const std::string& hintDir,
                           const NavLocation* origin) {
    Root* dec = rootByGroup(group, Root::Kind::Decompiled);
    if (!dec || !dec->tree) return false;
    const std::string path = symbols_.resolve(group, identifier, hintDir);
    if (path.empty()) return false;
    TreeNode* node = dec->tree->findByPath(path);
    if (!node || node->isFolder()) return false;
    navigateTo(*dec, *node, -1, origin);
    return true;
}

// ---------------------------------------------------------------------------
// Export / extract (M5)
// ---------------------------------------------------------------------------

bool Workspace::exportNode(Root& root, const TreeNode& node, const std::string& destFile, bool decoded) {
    if (node.isFolder()) return false;
    std::vector<uint8_t> bytes;
    if (!root.source || !root.source->read(node, bytes)) {
        log("Export failed: cannot read " + node.name());
        return false;
    }
    const fs::path dest = pathutil::fromUtf8(pathutil::normalize(destFile));
    std::string text;
    if (decoded && AxmlDecoder::looksLikeAxml(bytes)) {
        std::string error;
        if (AxmlDecoder::decode(bytes, text, error)) {
            std::ofstream out(dest, std::ios::binary);
            out.write(text.data(), (std::streamsize)text.size());
            if (!out) {
                log("Export failed: cannot write " + pathutil::toUtf8(dest));
                return false;
            }
            log("Exported decoded " + node.name() + " to " + pathutil::toUtf8(dest));
            return true;
        }
        // undecodable AXML falls through to the raw bytes
    }
    std::ofstream out(dest, std::ios::binary);
    if (!out) {
        log("Export failed: cannot write " + pathutil::toUtf8(dest));
        return false;
    }
    out.write(reinterpret_cast<const char*>(bytes.data()), (std::streamsize)bytes.size());
    if (!out) {
        log("Export failed: cannot write " + pathutil::toUtf8(dest));
        return false;
    }
    log("Exported " + node.name() + " to " + pathutil::toUtf8(dest));
    return true;
}

// Collects every file under `folder` (UI-thread tree walk) with paths
// relative to it - the archive entry path for APK roots, the disk path for
// decompiled roots.
void Workspace::collectExportItems(Root& root, const TreeNode& folder, const TreeNode& node,
                                   std::vector<ExportJob::Item>& items) const {
    if (node.isFolder()) {
        for (const auto& c : node.children()) collectExportItems(root, folder, *c, items);
        return;
    }
    const std::string& p = node.path();
    const std::string& base = folder.path();
    std::string rel;
    if (!base.empty() && p.rfind(base, 0) == 0 && p.size() > base.size() && p[base.size()] == '/')
        rel = p.substr(base.size() + 1);
    else
        rel = p;
    items.push_back({root.source, &node, std::move(rel)});
}

void Workspace::exportFolder(Root& root, const TreeNode& folder, const std::string& destDir, bool decoded) {
    std::vector<ExportJob::Item> items;
    collectExportItems(root, folder, folder, items);
    export_.start(destDir, std::move(items), decoded);
    log("Exporting " + folder.name() + " (" + std::to_string(export_.total()) + " file(s)) to " + destDir);
}

void Workspace::promoteDocument(Document* doc) {
    if (!doc || doc->isPreview()) return;
    doc->promote();
    bumpVersion();
}

void Workspace::closeDocument(const Document* doc) {
    if (pendingFocus_ == doc) pendingFocus_ = nullptr;
    if (activeDocument_ == doc) activeDocument_ = nullptr;
    for (auto it = documents_.begin(); it != documents_.end(); ++it) {
        if (it->get() == doc) {
            documents_.erase(it);
            bumpVersion();
            return;
        }
    }
}

void Workspace::closeAllDocuments() {
    if (documents_.empty()) return;
    pendingFocus_ = nullptr;
    activeDocument_ = nullptr;
    documents_.clear();
    bumpVersion();
}

void Workspace::closeAll() {
    search_.stop();
    documents_.clear();
    roots_.clear();
    pendingFocus_ = nullptr;
    activeDocument_ = nullptr;
    pendingTabs_.clear();
    nav_.clear();  // history is per project session
    symbols_.clear();
    treeEpochs_.clear();
    if (export_.busy()) export_.cancel();  // items point into the cleared trees
    jadxQueue_.clear();
    // An active jadx run is left alone: its output directory is orphaned and
    // its completion is ignored (jadxActiveGroup_ was cleared with the
    // roots), so a new project can be used while it winds down.
    jadxActiveGroup_.clear();
    bumpVersion();
}

Document* Workspace::takeFocusRequest() {
    Document* d = pendingFocus_;
    pendingFocus_ = nullptr;
    return d;
}

void Workspace::log(std::string message) { log_.push_back(std::move(message)); }

void Workspace::applyPendingTabs(Root::Kind kind, const std::string& group) {
    if (pendingTabs_.empty()) return;
    RootKind wanted = kind == Root::Kind::Decompiled ? RootKind::Decompiled : RootKind::Apk;
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
