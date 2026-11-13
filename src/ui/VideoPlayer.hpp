#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

// Plays a video (or AAC / M4A audio) file from memory. Decoding uses Windows
// Media Foundation (H.264, HEVC with the system extension, MPEG-4, WMV, AAC,
// MP3), so on other platforms open() reports that playback is unavailable.
// Video and audio decode on worker threads; frames are handed to the UI
// thread by takeFrame() when their time has come.
class VideoPlayer {
public:
    VideoPlayer();
    ~VideoPlayer();
    VideoPlayer(const VideoPlayer&) = delete;
    VideoPlayer& operator=(const VideoPlayer&) = delete;

    bool open(const std::vector<uint8_t>& bytes, std::string& error);
    bool isOpen() const;
    bool hasVideo() const;
    bool hasAudio() const;
    int width() const;
    int height() const;

    void play();
    void pause();
    bool playing() const;
    void seek(double seconds);
    void setVolume(float volume);
    double position() const;
    double duration() const;

    // The newest frame due for display (RGBA, width() x height()); false when
    // nothing new has to be shown. Call once per UI frame.
    bool takeFrame(std::vector<uint8_t>& rgba);

    static bool anyPlaying();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
