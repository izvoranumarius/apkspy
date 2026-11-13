#include "ui/AudioPlayer.hpp"
#include <algorithm>
#include <atomic>
#include <cmath>
#include <mutex>
#include <thread>

#include "ui/AudioConfig.hpp"
#include "miniaudio/miniaudio.h"  // the implementation lives in AudioCodecs.cpp

namespace {
constexpr int kBuckets = 1200;  // waveform resolution
std::atomic<int> sPlaying{0};   // players currently playing, so the app keeps drawing
}

bool AudioPlayer::anyPlaying() { return sPlaying.load() > 0; }

struct AudioPlayer::Impl {
    std::vector<uint8_t> data;
    ma_decoder decoder{};
    bool decoderOk = false;
    ma_device device{};
    bool deviceOk = false;
    std::string deviceError;
    mutable std::mutex mutex;  // guards decoder (audio thread vs. seek)
    std::atomic<bool> playing{false};
    std::atomic<uint64_t> cursor{0};
    uint64_t totalFrames = 0;
    int channels = 0;
    int sampleRate = 0;

    std::thread worker;
    std::atomic<bool> stopWorker{false};
    mutable std::mutex peaksMutex;
    std::vector<float> peaks;

    static void callback(ma_device* device, void* out, const void*, ma_uint32 frames) {
        auto* self = static_cast<Impl*>(device->pUserData);
        float* dst = static_cast<float*>(out);
        const size_t samples = static_cast<size_t>(frames) * static_cast<size_t>(self->channels);
        if (!self->playing.load()) {
            std::fill(dst, dst + samples, 0.f);
            return;
        }
        ma_uint64 read = 0;
        {
            std::lock_guard<std::mutex> lock(self->mutex);
            ma_decoder_read_pcm_frames(&self->decoder, dst, frames, &read);
        }
        self->cursor.fetch_add(read);
        if (read < frames) {
            std::fill(dst + read * static_cast<size_t>(self->channels), dst + samples, 0.f);
            if (self->playing.exchange(false)) sPlaying.fetch_sub(1);  // end of file: back to the start
            std::lock_guard<std::mutex> lock(self->mutex);
            ma_decoder_seek_to_pcm_frame(&self->decoder, 0);
            self->cursor.store(0);
        }
    }

    // A second decoder reads the whole file once for the waveform.
    void computePeaks() {
        ma_decoder_config cfg = ma_decoder_config_init(ma_format_f32, 1, 0);
        ma_decoder dec;
        if (ma_decoder_init_memory(data.data(), data.size(), &cfg, &dec) != MA_SUCCESS) return;
        std::vector<float> raw;  // peak per 256 frames
        std::vector<float> chunk(256);
        while (!stopWorker.load()) {
            ma_uint64 read = 0;
            if (ma_decoder_read_pcm_frames(&dec, chunk.data(), chunk.size(), &read) != MA_SUCCESS && read == 0) break;
            if (read == 0) break;
            float peak = 0.f;
            for (ma_uint64 i = 0; i < read; ++i) peak = std::max(peak, std::fabs(chunk[static_cast<size_t>(i)]));
            raw.push_back(std::min(peak, 1.f));
        }
        ma_decoder_uninit(&dec);
        if (stopWorker.load() || raw.empty()) return;
        const size_t buckets = std::min(raw.size(), static_cast<size_t>(kBuckets));
        std::vector<float> out(buckets, 0.f);
        for (size_t i = 0; i < raw.size(); ++i) {
            float& b = out[i * buckets / raw.size()];
            b = std::max(b, raw[i]);
        }
        std::lock_guard<std::mutex> lock(peaksMutex);
        peaks = std::move(out);
    }
};

AudioPlayer::AudioPlayer() : impl_(std::make_unique<Impl>()) {}

AudioPlayer::~AudioPlayer() {
    pause();
    impl_->stopWorker.store(true);
    if (impl_->worker.joinable()) impl_->worker.join();
    if (impl_->deviceOk) ma_device_uninit(&impl_->device);
    if (impl_->decoderOk) ma_decoder_uninit(&impl_->decoder);
}

bool AudioPlayer::open(const std::vector<uint8_t>& bytes, std::string& error) {
    Impl& d = *impl_;
    d.data = bytes;  // the player can outlive the document's buffer
    ma_decoder_config cfg = ma_decoder_config_init(ma_format_f32, 0, 0);
    if (ma_decoder_init_memory(d.data.data(), d.data.size(), &cfg, &d.decoder) != MA_SUCCESS) {
        error = "This audio format cannot be decoded (supported: WAV, MP3, FLAC, Ogg Vorbis)";
        return false;
    }
    d.decoderOk = true;
    d.channels = static_cast<int>(d.decoder.outputChannels);
    d.sampleRate = static_cast<int>(d.decoder.outputSampleRate);
    ma_uint64 frames = 0;
    if (ma_decoder_get_length_in_pcm_frames(&d.decoder, &frames) == MA_SUCCESS) d.totalFrames = frames;

    ma_device_config dc = ma_device_config_init(ma_device_type_playback);
    dc.playback.format = ma_format_f32;
    dc.playback.channels = d.decoder.outputChannels;
    dc.sampleRate = d.decoder.outputSampleRate;
    dc.dataCallback = &Impl::callback;
    dc.pUserData = &d;
    if (ma_device_init(nullptr, &dc, &d.device) == MA_SUCCESS) d.deviceOk = true;
    else d.deviceError = "No audio output device is available";
    d.worker = std::thread([&d] { d.computePeaks(); });
    return true;
}

bool AudioPlayer::isOpen() const { return impl_->decoderOk; }

void AudioPlayer::play() {
    if (!impl_->deviceOk) return;
    if (!impl_->playing.exchange(true)) sPlaying.fetch_add(1);
    if (ma_device_get_state(&impl_->device) != ma_device_state_started) ma_device_start(&impl_->device);
}

void AudioPlayer::pause() {
    if (impl_->playing.exchange(false)) sPlaying.fetch_sub(1);
}

bool AudioPlayer::playing() const { return impl_->playing.load(); }

void AudioPlayer::seek(double seconds) {
    if (!impl_->decoderOk || impl_->sampleRate <= 0) return;
    uint64_t frame = static_cast<uint64_t>(std::max(0.0, seconds * impl_->sampleRate));
    if (impl_->totalFrames) frame = std::min(frame, impl_->totalFrames);
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (ma_decoder_seek_to_pcm_frame(&impl_->decoder, frame) == MA_SUCCESS) impl_->cursor.store(frame);
}

void AudioPlayer::setVolume(float volume) {
    if (impl_->deviceOk) ma_device_set_master_volume(&impl_->device, std::clamp(volume, 0.f, 1.f));
}

double AudioPlayer::position() const {
    return impl_->sampleRate > 0 ? static_cast<double>(impl_->cursor.load()) / impl_->sampleRate : 0.0;
}

double AudioPlayer::duration() const {
    return impl_->sampleRate > 0 ? static_cast<double>(impl_->totalFrames) / impl_->sampleRate : 0.0;
}

int AudioPlayer::channels() const { return impl_->channels; }
int AudioPlayer::sampleRate() const { return impl_->sampleRate; }
const std::string& AudioPlayer::deviceError() const { return impl_->deviceError; }

std::vector<float> AudioPlayer::peaks() const {
    std::lock_guard<std::mutex> lock(impl_->peaksMutex);
    return impl_->peaks;
}
