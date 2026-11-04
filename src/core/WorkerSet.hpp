#pragma once
#include <atomic>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

// Threads that are joined once they finished (never blocking on a live one),
// plus joinAll() for shutdown.
class WorkerSet {
public:
    ~WorkerSet() { joinAll(); }
    template <typename F>
    void spawn(F&& fn) {
        reap();
        auto done = std::make_shared<std::atomic<bool>>(false);
        std::lock_guard<std::mutex> lock(m_);
        items_.push_back({std::thread([done, f = std::forward<F>(fn)]() mutable {
                              f();
                              *done = true;
                          }),
                          done});
    }
    void reap() {
        std::lock_guard<std::mutex> lock(m_);
        for (auto it = items_.begin(); it != items_.end();) {
            if (it->done->load()) {
                it->thread.join();
                it = items_.erase(it);
            } else {
                ++it;
            }
        }
    }
    void joinAll() {
        std::vector<Item> all;
        {
            std::lock_guard<std::mutex> lock(m_);
            all.swap(items_);
        }
        for (auto& i : all)
            if (i.thread.joinable()) i.thread.join();
    }

private:
    struct Item {
        std::thread thread;
        std::shared_ptr<std::atomic<bool>> done;
    };
    std::mutex m_;
    std::vector<Item> items_;
};
