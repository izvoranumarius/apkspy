#pragma once
#include <memory>
#include <string>
#include <vector>
#include "ui/AudioPlayer.hpp"
#include "ui/HexView.hpp"
#include "ui/VideoPlayer.hpp"

class Texture;

// Audio file: format details, waveform, play / pause / seek and volume.
class AudioView {
public:
    void draw(const std::vector<uint8_t>& bytes);

private:
    AudioPlayer player_;
    bool opened_ = false;
    std::string error_;
    std::string format_;
    float volume_ = 0.8f;
    bool showHex_ = false;
    HexView hex_;
};

// Video file (and AAC / M4A audio): picture scaled to fit, play / pause,
// seek bar and volume.
class VideoView {
public:
    VideoView();
    ~VideoView();
    void draw(const std::vector<uint8_t>& bytes);

private:
    VideoPlayer player_;
    bool opened_ = false;
    std::string error_;
    std::string format_;
    float volume_ = 0.8f;
    bool showHex_ = false;
    HexView hex_;
    std::unique_ptr<Texture> texture_;
    std::vector<uint8_t> frame_;
};

// Font file (TTF / OTF / TTC): names, sample text at several sizes and the
// first glyphs, rendered with stb_truetype into one texture.
class FontView {
public:
    FontView();
    ~FontView();
    void draw(const std::vector<uint8_t>& bytes);

private:
    void render(const std::vector<uint8_t>& bytes);

    bool rendered_ = false;
    std::string error_;
    std::string family_;
    std::string fullName_;
    int glyphs_ = 0;
    std::unique_ptr<Texture> texture_;
    bool showHex_ = false;
    HexView hex_;
};
