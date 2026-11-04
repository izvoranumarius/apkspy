#include "analysis/AnalysisService.hpp"
#include <algorithm>
#include <cstdio>
#include "core/ApkArchive.hpp"

namespace {

// classes.dex, classes2.dex, ... in numeric order (the order ART loads them).
bool dexOrder(const std::string& a, const std::string& b) {
    const auto num = [](const std::string& s) {
        // "classes.dex" = 1, "classesN.dex" = N
        const std::string mid = s.substr(7, s.size() - 7 - 4);
        if (mid.empty()) return 1;
        int n = 0;
        for (char c : mid) n = n * 10 + (c - '0');
        return n;
    };
    return num(a) < num(b);
}

bool isRootDex(const std::string& path) {
    if (path.size() < 11 || path.compare(0, 7, "classes") != 0 || path.compare(path.size() - 4, 4, ".dex") != 0)
        return false;
    for (size_t i = 7; i < path.size() - 4; ++i)
        if (path[i] < '0' || path[i] > '9') return false;
    return true;
}

}  // namespace

AnalysisService::~AnalysisService() { clear(); }

void AnalysisService::stopJob(Job& job) {
    job.stop = true;
    if (job.worker.joinable()) job.worker.join();
}

void AnalysisService::start(const std::string& group, const std::string& apkPath, bool force) {
    std::unique_ptr<Job> old;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = jobs_.find(group);
        if (it != jobs_.end()) {
            Job& j = *it->second;
            State s;
            {
                std::lock_guard<std::mutex> jl(j.mutex);
                s = j.state;
            }
            if (!force && j.apkPath == apkPath && (s == State::Running || s == State::Ready)) return;
            old = std::move(it->second);
            jobs_.erase(it);
        }
    }
    if (old) {
        old->stop = true;
        {
            std::lock_guard<std::mutex> jl(old->mutex);
            old->result.reset();  // the replaced result is not kept alive
        }
        std::lock_guard<std::mutex> lock(mutex_);
        retired_.push_back(std::move(old));  // joined in update(): never block here
    }
    auto job = std::make_unique<Job>();
    job->apkPath = apkPath;
    Job* raw = job.get();
    job->worker = std::thread(&AnalysisService::run, raw);
    std::lock_guard<std::mutex> lock(mutex_);
    jobs_[group] = std::move(job);
}

void AnalysisService::run(Job* job) {
    const auto setPhase = [&](std::string p) {
        std::lock_guard<std::mutex> lock(job->mutex);
        job->phase = std::move(p);
    };
    const auto finish = [&](State s, std::string error, std::shared_ptr<const ApkAnalysis> result) {
        {
            std::lock_guard<std::mutex> lock(job->mutex);
            job->state = s;
            job->error = std::move(error);
            job->result = std::move(result);
            job->phase.clear();
        }
        job->finished = true;
    };

    ApkArchive archive;  // private handle: thread-confined
    if (!archive.open(job->apkPath)) {
        finish(State::Failed, "cannot open " + job->apkPath, nullptr);
        return;
    }
    std::vector<std::string> dexNames;
    for (const ApkArchive::Entry& e : archive.entries())
        if (isRootDex(e.path)) dexNames.push_back(e.path);
    std::sort(dexNames.begin(), dexNames.end(), dexOrder);
    if (dexNames.empty()) {
        finish(State::Failed, "the APK contains no classes*.dex", nullptr);
        return;
    }
    std::vector<std::shared_ptr<DexFile>> dexes;
    std::string warnings;
    for (const std::string& name : dexNames) {
        if (job->stop.load()) {
            finish(State::Cancelled, {}, nullptr);
            return;
        }
        setPhase("reading " + name);
        auto bytes = std::make_shared<std::vector<uint8_t>>();
        if (!archive.readEntry(name, *bytes, 512ull * 1024 * 1024)) {
            warnings += "cannot read " + name + "; ";
            continue;
        }
        std::string error;
        auto dex = DexFile::parse(std::move(bytes), name, error);
        if (!dex) {
            warnings += name + ": " + error + "; ";
            continue;
        }
        dexes.push_back(std::move(dex));
    }
    archive.close();
    if (dexes.empty()) {
        finish(State::Failed, warnings.empty() ? "no usable DEX file" : warnings, nullptr);
        return;
    }
    setPhase("indexing bytecode");
    auto result = ApkAnalysis::build(std::move(dexes), job->stop, &job->done, &job->total);
    if (!result) {
        finish(State::Cancelled, {}, nullptr);
        return;
    }
    finish(State::Ready, warnings, std::move(result));
}

void AnalysisService::cancel(const std::string& group) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = jobs_.find(group);
    if (it != jobs_.end()) it->second->stop = true;
}

void AnalysisService::purge(const std::string& group) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = jobs_.find(group);
    if (it == jobs_.end()) return;
    it->second->stop = true;
    {
        // Release the result now (not when the worker is reaped): the DEX
        // data and xref tables go away as soon as no reader holds them.
        std::lock_guard<std::mutex> jl(it->second->mutex);
        it->second->result.reset();
    }
    retired_.push_back(std::move(it->second));
    jobs_.erase(it);
}

void AnalysisService::clear() {
    std::vector<std::unique_ptr<Job>> all;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& kv : jobs_) all.push_back(std::move(kv.second));
        jobs_.clear();
        for (auto& j : retired_) all.push_back(std::move(j));
        retired_.clear();
    }
    for (auto& j : all) j->stop = true;
    for (auto& j : all) stopJob(*j);
    std::lock_guard<std::mutex> lock(elfMutex_);
    lastNative_.reset();
}

void AnalysisService::update() {
    std::vector<std::unique_ptr<Job>> done;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto it = retired_.begin(); it != retired_.end();) {
            if ((*it)->finished.load()) {
                done.push_back(std::move(*it));
                it = retired_.erase(it);
            } else {
                ++it;
            }
        }
        for (auto& kv : jobs_)
            if (kv.second->finished.load() && kv.second->worker.joinable()) kv.second->worker.join();
    }
    for (auto& j : done) stopJob(*j);  // already finished: join is immediate
}

AnalysisService::Status AnalysisService::status(const std::string& group) const {
    Status st;
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = jobs_.find(group);
    if (it == jobs_.end()) return st;
    const Job& j = *it->second;
    std::lock_guard<std::mutex> jl(j.mutex);
    st.state = j.state;
    st.error = j.error;
    st.phase = j.phase;
    st.done = j.done.load();
    st.total = j.total.load();
    return st;
}

std::shared_ptr<const ApkAnalysis> AnalysisService::get(const std::string& group) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = jobs_.find(group);
    if (it == jobs_.end()) return nullptr;
    std::lock_guard<std::mutex> jl(it->second->mutex);
    return it->second->result;
}

std::vector<std::string> AnalysisService::groups() const {
    std::vector<std::string> out;
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& kv : jobs_) out.push_back(kv.first);
    std::sort(out.begin(), out.end());
    return out;
}

std::shared_ptr<const ElfFile> AnalysisService::loadElf(const std::string& apkPath, const std::string& entry,
                                                        std::string& error) {
    const std::string key = apkPath + '\n' + entry;
    {
        std::lock_guard<std::mutex> lock(elfMutex_);
        auto it = elfCache_.find(key);
        if (it != elfCache_.end())
            if (auto alive = it->second.lock()) return alive;
    }
    ApkArchive archive;
    if (!archive.open(apkPath)) {
        error = "cannot open " + apkPath;
        return nullptr;
    }
    auto bytes = std::make_shared<std::vector<uint8_t>>();
    if (!archive.readEntry(entry, *bytes, 512ull * 1024 * 1024)) {
        error = "cannot read " + entry;
        return nullptr;
    }
    std::shared_ptr<const ElfFile> elf = ElfFile::parse(std::move(bytes), entry, error);
    if (!elf) return nullptr;
    std::lock_guard<std::mutex> lock(elfMutex_);
    // The cache only holds weak references: a library stays in memory only
    // while some view / tool result still uses it.
    for (auto it = elfCache_.begin(); it != elfCache_.end();)
        it = it->second.expired() ? elfCache_.erase(it) : std::next(it);
    elfCache_[key] = elf;
    return elf;
}

std::shared_ptr<const NativeCode> AnalysisService::loadNative(const std::string& apkPath, const std::string& entry,
                                                              const std::atomic<bool>* cancel, std::string& error) {
    const std::string key = apkPath + '\n' + entry;
    {
        std::lock_guard<std::mutex> lock(elfMutex_);
        auto it = nativeCache_.find(key);
        if (it != nativeCache_.end())
            if (auto alive = it->second.lock()) {
                lastNative_ = alive;
                return alive;
            }
    }
    std::shared_ptr<const ElfFile> elf = loadElf(apkPath, entry, error);
    if (!elf) return nullptr;
    std::shared_ptr<const NativeCode> code = NativeCode::build(elf, cancel, error);
    if (!code) return nullptr;
    std::lock_guard<std::mutex> lock(elfMutex_);
    for (auto it = nativeCache_.begin(); it != nativeCache_.end();)
        it = it->second.expired() ? nativeCache_.erase(it) : std::next(it);
    nativeCache_[key] = code;
    lastNative_ = code;
    return code;
}
