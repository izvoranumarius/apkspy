#pragma once
#include <string>
#include <vector>
#include "core/Codec.hpp"
#include "ui/Panel.hpp"

// "Decoder": text in, a chain of steps (Base64, hex, URL, escapes, charsets,
// XOR, zlib / gzip, hashes, JWT), the result out, recomputed as you type, as in
// CyberChef or Burp's Decoder. "Send to Decoder" in the strings lists, code
// views and Output fills the input and decodes it layer by layer.
class DecoderPanel : public Panel {
public:
    explicit DecoderPanel(Workspace& workspace) : Panel(workspace, "Decoder") {}

    // New input; `smart` replaces the steps with the decoding the input looks like.
    void setInput(std::string text, bool smart = true);

protected:
    void drawContents() override;

private:
    struct Step {
        codec::Op op;
        std::string arg;
        bool enabled = true;
    };
    void recompute();
    void smartDecode();
    void drawInput(float height);
    void drawSteps();
    void drawOutput();
    bool opMenu(codec::Op& chosen);  // grouped operation list; true when one was picked

    std::string input_;
    std::vector<Step> steps_;
    std::vector<codec::Result> results_;  // per step (disabled steps pass their input on)
    std::string output_;                  // what the last step produced
    std::string shown_;                   // output_ as text or a hex dump
    int failed_ = -1;                     // first step that failed
    int view_ = 0;                        // 0 auto, 1 text, 2 hex
    bool dirty_ = true;
    std::string note_;                    // "Smart decode: Base64 decode > Inflate"
    std::vector<codec::Op> guesses_;      // what the input looks like (offered as one-click steps)
};
