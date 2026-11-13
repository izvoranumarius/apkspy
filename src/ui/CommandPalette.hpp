#pragma once
#include <functional>
#include <string>
#include <vector>

class Workspace;
struct Root;
class TreeNode;

// One box for getting anywhere, as in VS Code, Binary Ninja and IDA's Jump
// Anywhere. What it searches depends on the first character:
//   (none)  files of every APK and its decompiled sources   (Ctrl+P)
//   >       commands                                         (Ctrl+Shift+P)
//   @       classes of the analysed APKs
//   :       a line in the current file
// Matching is fuzzy: the typed letters in order, with matches at word
// starts and in the file name ranked first.
class CommandPalette {
public:
    struct Command {
        std::string name;
        std::string shortcut;
        const char* icon = nullptr;
        std::function<void()> run;
    };

    explicit CommandPalette(Workspace& workspace) : workspace_(workspace) {}
    void setCommands(std::function<std::vector<Command>()> provider) { commands_ = std::move(provider); }
    // What to show when a file or class is opened (the editor panel).
    void setShowEditor(std::function<void()> show) { showEditor_ = std::move(show); }

    void open(const std::string& prefix);
    void draw();

    // Fuzzy score of `pattern` in `text` (higher is better), or -1 when the
    // letters do not all appear in order. Exposed for the tests.
    static int fuzzyScore(const std::string& pattern, const std::string& text);

private:
    struct Item {
        std::string label;   // what is matched and shown
        std::string detail;  // dimmed, after the label
        const char* icon = nullptr;
        int kind = 0;        // 0 file, 1 command, 2 class, 3 line
        Root* root = nullptr;
        const TreeNode* node = nullptr;
        size_t command = 0;
        std::string group;   // class: the APK
        int line = 0;
        int score = 0;
    };
    void collect();
    void filter();
    void accept(const Item& item);

    Workspace& workspace_;
    std::function<std::vector<Command>()> commands_;
    std::function<void()> showEditor_;
    bool openRequest_ = false;
    char query_[256] = {};
    std::string applied_ = "\x01";
    std::vector<Item> files_, classes_;
    std::vector<Command> commandList_;
    std::vector<Item> shown_;
    int selected_ = 0;
    bool scrollToSelected_ = false;
};
