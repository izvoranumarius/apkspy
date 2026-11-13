#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

// Plays one audio file from memory (WAV, MP3, FLAC, Ogg Vorbis through
// miniaudio) and computes a waveform overview on a worker thread.
class AudioPlayer {
public:
    AudioPlayer();
    ~AudioPlayer();
    AudioPlayer(const AudioPlayer&) = delete;
    AudioPlayer& operator=(const AudioPlayer&) = delete;

    bool open(const std::vector<uint8_t>& bytes, std::string& error);
    bool isOpen() const;

    void play();
    void pause();
    bool playing() const;
    void seek(double seconds);
    void setVolume(float volume);  // 0..1

    double position() const;  // seconds
    double duration() const;  // seconds, 0 when unknown
    int channels() const;
    int sampleRate() const;
    const std::string& deviceError() const;  // set when no output device could be opened

    // Peak per bucket (0..1), empty until the worker has finished.
    std::vector<float> peaks() const;

    // True while any player is playing (the app then redraws continuously).
    static bool anyPlaying();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
