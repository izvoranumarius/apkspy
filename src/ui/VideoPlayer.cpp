#include "ui/VideoPlayer.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <future>
#include <mutex>
#include <thread>

namespace {
std::atomic<int> sPlaying{0};
}

bool VideoPlayer::anyPlaying() { return sPlaying.load() > 0; }

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <mfapi.h>
#include <mferror.h>
#include <mfidl.h>
#include <mfreadwrite.h>
#include <shlwapi.h>
#include "miniaudio/miniaudio.h"  // the implementation lives in AudioPlayer.cpp

#pragma comment(lib, "mfplat.lib")
#pragma comment(lib, "mfreadwrite.lib")
#pragma comment(lib, "mfuuid.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ole32.lib")

namespace {

using Clock = std::chrono::steady_clock;
constexpr size_t kMaxFrames = 3;           // decoded frames waiting for their time
constexpr double kAudioBufferSeconds = 1.0;  // decoded audio kept ahead
constexpr UINT32 kMaxSide = 1920;           // larger pictures are scaled down while decoding

template <typename T>
void release(T*& p) {
    if (p) p->Release();
    p = nullptr;
}

bool startMediaFoundation() {
    static const bool ok = SUCCEEDED(MFStartup(MF_VERSION, MFSTARTUP_LITE));
    return ok;
}

// A source reader over the file bytes, with only one stream selected.
IMFSourceReader* makeReader(const std::vector<uint8_t>& data, DWORD stream, bool videoProcessing) {
    IStream* mem = SHCreateMemStream(data.data(), (UINT)data.size());
    if (!mem) return nullptr;
    IMFByteStream* bytes = nullptr;
    HRESULT hr = MFCreateMFByteStreamOnStream(mem, &bytes);
    mem->Release();
    if (FAILED(hr)) return nullptr;
    // A content type helps Media Foundation pick the right parser.
    IMFAttributes* streamAttrs = nullptr;
    if (SUCCEEDED(bytes->QueryInterface(IID_PPV_ARGS(&streamAttrs)))) {
        if (data.size() > 12 && std::memcmp(data.data() + 4, "ftyp", 4) == 0)
            streamAttrs->SetString(MF_BYTESTREAM_CONTENT_TYPE, L"video/mp4");
        else if (data.size() > 4 && std::memcmp(data.data(), "\x1A\x45\xDF\xA3", 4) == 0)
            streamAttrs->SetString(MF_BYTESTREAM_CONTENT_TYPE, L"video/webm");
        streamAttrs->Release();
    }
    IMFAttributes* attrs = nullptr;
    MFCreateAttributes(&attrs, 2);
    // Advanced processing converts to RGB and can also scale the picture down.
    if (attrs && videoProcessing) attrs->SetUINT32(MF_SOURCE_READER_ENABLE_ADVANCED_VIDEO_PROCESSING, TRUE);
    IMFSourceReader* reader = nullptr;
    hr = MFCreateSourceReaderFromByteStream(bytes, attrs, &reader);
    if (attrs) attrs->Release();
    bytes->Release();
    if (FAILED(hr)) return nullptr;
    reader->SetStreamSelection((DWORD)MF_SOURCE_READER_ALL_STREAMS, FALSE);
    if (FAILED(reader->SetStreamSelection(stream, TRUE))) {
        reader->Release();
        return nullptr;
    }
    return reader;
}

void seekReader(IMFSourceReader* reader, double seconds) {
    PROPVARIANT pos;
    PropVariantInit(&pos);
    pos.vt = VT_I8;
    pos.hVal.QuadPart = (LONGLONG)(seconds * 1e7);
    reader->SetCurrentPosition(GUID_NULL, pos);
    PropVariantClear(&pos);
}

}  // namespace

struct VideoPlayer::Impl {
    std::vector<uint8_t> data;
    std::atomic<bool> stop{false};
    bool opened = false;
    bool video = false, audio = false;
    int width = 0, height = 0;
    double duration = 0.0;

    // Clock: seconds into the file.
    mutable std::mutex clockMutex;
    std::atomic<bool> playing{false};
    double clockBase = 0.0;
    Clock::time_point playStart;

    // Video frames.
    struct Frame {
        double time;
        std::vector<uint8_t> rgba;
    };
    std::mutex frameMutex;
    std::condition_variable frameCv;
    std::deque<Frame> frames;
    bool videoEof = false;
    std::atomic<double> seekVideo{-1.0};
    std::thread videoThread;
    bool firstFrame = true;

    // Audio samples (interleaved float), played through miniaudio.
    int channels = 0, sampleRate = 0;
    std::mutex audioMutex;
    std::condition_variable audioCv;
    std::deque<float> samples;
    std::atomic<double> seekAudio{-1.0};
    std::thread audioThread;
    ma_device device{};
    bool deviceOk = false;

    double clock() const {
        std::lock_guard<std::mutex> lock(clockMutex);
        if (!playing.load()) return clockBase;
        return clockBase + std::chrono::duration<double>(Clock::now() - playStart).count();
    }

    static void audioCallback(ma_device* dev, void* out, const void*, ma_uint32 frameCount) {
        auto* self = static_cast<Impl*>(dev->pUserData);
        float* dst = static_cast<float*>(out);
        const size_t want = (size_t)frameCount * (size_t)self->channels;
        size_t got = 0;
        if (self->playing.load()) {
            std::lock_guard<std::mutex> lock(self->audioMutex);
            got = std::min(want, self->samples.size());
            std::copy(self->samples.begin(), self->samples.begin() + (ptrdiff_t)got, dst);
            self->samples.erase(self->samples.begin(), self->samples.begin() + (ptrdiff_t)got);
        }
        std::fill(dst + got, dst + want, 0.f);
        self->audioCv.notify_one();
    }

    void videoLoop(std::promise<void> ready) {
        CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        IMFSourceReader* reader = makeReader(data, (DWORD)MF_SOURCE_READER_FIRST_VIDEO_STREAM, true);
        LONG stride = 0;
        if (reader) {
            // The file's own size, scaled to fit kMaxSide (a 4K frame is 33 MB as RGBA).
            UINT32 nativeW = 0, nativeH = 0;
            IMFMediaType* native = nullptr;
            if (SUCCEEDED(reader->GetNativeMediaType((DWORD)MF_SOURCE_READER_FIRST_VIDEO_STREAM, 0, &native))) {
                MFGetAttributeSize(native, MF_MT_FRAME_SIZE, &nativeW, &nativeH);
                native->Release();
            }
            IMFMediaType* type = nullptr;
            MFCreateMediaType(&type);
            type->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
            type->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_RGB32);
            bool typeOk = false;
            if (nativeW > kMaxSide || nativeH > kMaxSide) {
                const double scale = (double)kMaxSide / (double)std::max(nativeW, nativeH);
                const UINT32 w = std::max<UINT32>(2, (UINT32)(nativeW * scale) & ~1u);
                const UINT32 h = std::max<UINT32>(2, (UINT32)(nativeH * scale) & ~1u);
                MFSetAttributeSize(type, MF_MT_FRAME_SIZE, w, h);
                typeOk = SUCCEEDED(reader->SetCurrentMediaType((DWORD)MF_SOURCE_READER_FIRST_VIDEO_STREAM, nullptr, type));
                if (!typeOk) type->DeleteItem(MF_MT_FRAME_SIZE);  // full size, then
            }
            if (!typeOk) typeOk = SUCCEEDED(reader->SetCurrentMediaType((DWORD)MF_SOURCE_READER_FIRST_VIDEO_STREAM, nullptr, type));
            if (typeOk) {
                IMFMediaType* current = nullptr;
                if (SUCCEEDED(reader->GetCurrentMediaType((DWORD)MF_SOURCE_READER_FIRST_VIDEO_STREAM, &current))) {
                    UINT32 w = 0, h = 0;
                    MFGetAttributeSize(current, MF_MT_FRAME_SIZE, &w, &h);
                    width = (int)w;
                    height = (int)h;
                    UINT32 s = 0;
                    stride = SUCCEEDED(current->GetUINT32(MF_MT_DEFAULT_STRIDE, &s)) ? (LONG)(INT32)s : (LONG)w * 4;
                    current->Release();
                    video = width > 0 && height > 0;
                }
            }
            type->Release();
            PROPVARIANT var;
            PropVariantInit(&var);
            if (SUCCEEDED(reader->GetPresentationAttribute((DWORD)MF_SOURCE_READER_MEDIASOURCE, MF_PD_DURATION, &var)))
                duration = (double)var.uhVal.QuadPart / 1e7;
            PropVariantClear(&var);
            if (!video) release(reader);
        }
        ready.set_value();
        while (reader && !stop.load()) {
            const double target = seekVideo.exchange(-1.0);
            if (target >= 0.0) {
                seekReader(reader, target);
                std::lock_guard<std::mutex> lock(frameMutex);
                frames.clear();
                videoEof = false;
            }
            {
                std::unique_lock<std::mutex> lock(frameMutex);
                if (frames.size() >= kMaxFrames || videoEof) {
                    frameCv.wait_for(lock, std::chrono::milliseconds(10));
                    continue;
                }
            }
            DWORD flags = 0;
            LONGLONG ts = 0;
            IMFSample* sample = nullptr;
            if (FAILED(reader->ReadSample((DWORD)MF_SOURCE_READER_FIRST_VIDEO_STREAM, 0, nullptr, &flags, &ts, &sample))) {
                std::lock_guard<std::mutex> lock(frameMutex);
                videoEof = true;
                continue;
            }
            if (flags & MF_SOURCE_READERF_ENDOFSTREAM) {
                std::lock_guard<std::mutex> lock(frameMutex);
                videoEof = true;
            }
            if (!sample) continue;
            IMFMediaBuffer* buffer = nullptr;
            if (SUCCEEDED(sample->ConvertToContiguousBuffer(&buffer))) {
                BYTE* p = nullptr;
                DWORD len = 0;
                if (SUCCEEDED(buffer->Lock(&p, nullptr, &len))) {
                    Frame f;
                    f.time = (double)ts / 1e7;
                    f.rgba.resize((size_t)width * (size_t)height * 4);
                    const LONG pitch = stride == 0 ? width * 4 : std::abs(stride);
                    for (int y = 0; y < height; ++y) {
                        const int srcRow = stride < 0 ? height - 1 - y : y;
                        if ((size_t)(srcRow + 1) * (size_t)pitch > len) break;
                        const BYTE* src = p + (size_t)srcRow * (size_t)pitch;
                        uint8_t* dst = &f.rgba[(size_t)y * (size_t)width * 4];
                        for (int x = 0; x < width; ++x) {  // BGRX -> RGBA
                            dst[x * 4 + 0] = src[x * 4 + 2];
                            dst[x * 4 + 1] = src[x * 4 + 1];
                            dst[x * 4 + 2] = src[x * 4 + 0];
                            dst[x * 4 + 3] = 255;
                        }
                    }
                    buffer->Unlock();
                    std::lock_guard<std::mutex> lock(frameMutex);
                    if (seekVideo.load() < 0.0) frames.push_back(std::move(f));
                }
                buffer->Release();
            }
            sample->Release();
        }
        release(reader);
        CoUninitialize();
    }

    void audioLoop(std::promise<void> ready) {
        CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        IMFSourceReader* reader = makeReader(data, (DWORD)MF_SOURCE_READER_FIRST_AUDIO_STREAM, false);
        if (reader) {
            IMFMediaType* type = nullptr;
            MFCreateMediaType(&type);
            type->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Audio);
            type->SetGUID(MF_MT_SUBTYPE, MFAudioFormat_Float);
            if (SUCCEEDED(reader->SetCurrentMediaType((DWORD)MF_SOURCE_READER_FIRST_AUDIO_STREAM, nullptr, type))) {
                IMFMediaType* current = nullptr;
                if (SUCCEEDED(reader->GetCurrentMediaType((DWORD)MF_SOURCE_READER_FIRST_AUDIO_STREAM, &current))) {
                    channels = (int)MFGetAttributeUINT32(current, MF_MT_AUDIO_NUM_CHANNELS, 0);
                    sampleRate = (int)MFGetAttributeUINT32(current, MF_MT_AUDIO_SAMPLES_PER_SECOND, 0);
                    current->Release();
                    audio = channels > 0 && sampleRate > 0;
                }
            }
            type->Release();
            if (duration <= 0.0) {
                PROPVARIANT var;
                PropVariantInit(&var);
                if (SUCCEEDED(reader->GetPresentationAttribute((DWORD)MF_SOURCE_READER_MEDIASOURCE, MF_PD_DURATION, &var)))
                    duration = (double)var.uhVal.QuadPart / 1e7;
                PropVariantClear(&var);
            }
            if (!audio) release(reader);
        }
        ready.set_value();
        bool eof = false;
        while (reader && !stop.load()) {
            const double target = seekAudio.exchange(-1.0);
            if (target >= 0.0) {
                seekReader(reader, target);
                std::lock_guard<std::mutex> lock(audioMutex);
                samples.clear();
                eof = false;
            }
            {
                std::unique_lock<std::mutex> lock(audioMutex);
                if (eof || samples.size() >= (size_t)(kAudioBufferSeconds * sampleRate * channels)) {
                    audioCv.wait_for(lock, std::chrono::milliseconds(10));
                    continue;
                }
            }
            DWORD flags = 0;
            LONGLONG ts = 0;
            IMFSample* sample = nullptr;
            if (FAILED(reader->ReadSample((DWORD)MF_SOURCE_READER_FIRST_AUDIO_STREAM, 0, nullptr, &flags, &ts, &sample))) {
                eof = true;
                continue;
            }
            if (flags & MF_SOURCE_READERF_ENDOFSTREAM) eof = true;
            if (!sample) continue;
            IMFMediaBuffer* buffer = nullptr;
            if (SUCCEEDED(sample->ConvertToContiguousBuffer(&buffer))) {
                BYTE* p = nullptr;
                DWORD len = 0;
                if (SUCCEEDED(buffer->Lock(&p, nullptr, &len))) {
                    const float* f = reinterpret_cast<const float*>(p);
                    std::lock_guard<std::mutex> lock(audioMutex);
                    if (seekAudio.load() < 0.0) samples.insert(samples.end(), f, f + len / sizeof(float));
                    buffer->Unlock();
                }
                buffer->Release();
            }
            sample->Release();
        }
        release(reader);
        CoUninitialize();
    }
};

VideoPlayer::VideoPlayer() : impl_(std::make_unique<Impl>()) {}

VideoPlayer::~VideoPlayer() {
    pause();
    Impl& d = *impl_;
    d.stop.store(true);
    d.frameCv.notify_all();
    d.audioCv.notify_all();
    if (d.deviceOk) ma_device_uninit(&d.device);
    if (d.videoThread.joinable()) d.videoThread.join();
    if (d.audioThread.joinable()) d.audioThread.join();
}

bool VideoPlayer::open(const std::vector<uint8_t>& bytes, std::string& error) {
    Impl& d = *impl_;
    if (!startMediaFoundation()) {
        error = "Windows Media Foundation is not available on this system";
        return false;
    }
    d.data = bytes;
    std::promise<void> videoReady, audioReady;
    auto v = videoReady.get_future(), a = audioReady.get_future();
    d.videoThread = std::thread([&d, p = std::move(videoReady)]() mutable { d.videoLoop(std::move(p)); });
    d.audioThread = std::thread([&d, p = std::move(audioReady)]() mutable { d.audioLoop(std::move(p)); });
    v.wait();
    a.wait();
    if (!d.video && !d.audio) {
        error = "This file cannot be decoded. Windows plays MP4 (H.264), 3GP, AAC and WMV; "
                "WebM, HEVC and others need the matching codec from the Microsoft Store.";
        return false;
    }
    if (d.audio) {
        ma_device_config dc = ma_device_config_init(ma_device_type_playback);
        dc.playback.format = ma_format_f32;
        dc.playback.channels = (ma_uint32)d.channels;
        dc.sampleRate = (ma_uint32)d.sampleRate;
        dc.dataCallback = &Impl::audioCallback;
        dc.pUserData = &d;
        d.deviceOk = ma_device_init(nullptr, &dc, &d.device) == MA_SUCCESS && ma_device_start(&d.device) == MA_SUCCESS;
    }
    d.opened = true;
    return true;
}

bool VideoPlayer::isOpen() const { return impl_->opened; }
bool VideoPlayer::hasVideo() const { return impl_->video; }
bool VideoPlayer::hasAudio() const { return impl_->audio; }
int VideoPlayer::width() const { return impl_->width; }
int VideoPlayer::height() const { return impl_->height; }

void VideoPlayer::play() {
    Impl& d = *impl_;
    if (!d.opened || d.playing.load()) return;
    if (d.duration > 0.0 && d.clockBase >= d.duration - 0.05) seek(0.0);  // ended: start over
    std::lock_guard<std::mutex> lock(d.clockMutex);
    d.playStart = Clock::now();
    d.playing.store(true);
    sPlaying.fetch_add(1);
}

void VideoPlayer::pause() {
    Impl& d = *impl_;
    if (!d.playing.load()) return;
    const double now = d.clock();
    std::lock_guard<std::mutex> lock(d.clockMutex);
    d.clockBase = now;
    d.playing.store(false);
    sPlaying.fetch_sub(1);
}

bool VideoPlayer::playing() const { return impl_->playing.load(); }

void VideoPlayer::seek(double seconds) {
    Impl& d = *impl_;
    if (!d.opened) return;
    seconds = std::clamp(seconds, 0.0, d.duration > 0.0 ? d.duration : seconds);
    {
        std::lock_guard<std::mutex> lock(d.clockMutex);
        d.clockBase = seconds;
        d.playStart = Clock::now();
    }
    d.seekVideo.store(seconds);
    d.seekAudio.store(seconds);
    {
        std::lock_guard<std::mutex> lock(d.frameMutex);
        d.frames.clear();
        d.firstFrame = true;  // show the frame at the new position even while paused
    }
    {
        std::lock_guard<std::mutex> lock(d.audioMutex);
        d.samples.clear();
    }
    d.frameCv.notify_all();
    d.audioCv.notify_all();
}

void VideoPlayer::setVolume(float volume) {
    if (impl_->deviceOk) ma_device_set_master_volume(&impl_->device, std::clamp(volume, 0.f, 1.f));
}

double VideoPlayer::position() const { return std::min(impl_->clock(), impl_->duration > 0 ? impl_->duration : 1e18); }
double VideoPlayer::duration() const { return impl_->duration; }

bool VideoPlayer::takeFrame(std::vector<uint8_t>& rgba) {
    Impl& d = *impl_;
    const double now = d.clock();
    bool got = false;
    bool ended = false;
    {
        std::lock_guard<std::mutex> lock(d.frameMutex);
        // Before playback (or after a seek) show the first decoded frame.
        if (d.firstFrame && !d.frames.empty()) {
            rgba = std::move(d.frames.front().rgba);
            d.frames.pop_front();
            d.firstFrame = false;
            got = true;
        }
        while (!d.frames.empty() && d.frames.front().time <= now) {
            rgba = std::move(d.frames.front().rgba);
            d.frames.pop_front();
            got = true;
        }
        ended = d.videoEof && d.frames.empty();
    }
    if (got) d.frameCv.notify_one();
    // Playback ends with the longer of the two streams.
    if (d.playing.load() && d.duration > 0.0 && now >= d.duration && (ended || !d.video)) {
        pause();
        std::lock_guard<std::mutex> lock(d.clockMutex);
        d.clockBase = d.duration;
    }
    return got;
}

#else  // !_WIN32

struct VideoPlayer::Impl {};
VideoPlayer::VideoPlayer() : impl_(std::make_unique<Impl>()) {}
VideoPlayer::~VideoPlayer() = default;
bool VideoPlayer::open(const std::vector<uint8_t>&, std::string& error) {
    error = "Video playback is available in the Windows build";
    return false;
}
bool VideoPlayer::isOpen() const { return false; }
bool VideoPlayer::hasVideo() const { return false; }
bool VideoPlayer::hasAudio() const { return false; }
int VideoPlayer::width() const { return 0; }
int VideoPlayer::height() const { return 0; }
void VideoPlayer::play() {}
void VideoPlayer::pause() {}
bool VideoPlayer::playing() const { return false; }
void VideoPlayer::seek(double) {}
void VideoPlayer::setVolume(float) {}
double VideoPlayer::position() const { return 0.0; }
double VideoPlayer::duration() const { return 0.0; }
bool VideoPlayer::takeFrame(std::vector<uint8_t>&) { return false; }

#endif
