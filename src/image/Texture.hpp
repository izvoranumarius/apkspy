#pragma once
#include <cstdint>

class Texture {
public:
    Texture(const uint8_t* rgba, int width, int height);
    ~Texture();
    Texture(const Texture&) = delete;
    Texture& operator=(const Texture&) = delete;

    unsigned int id() const { return id_; }
    int width() const { return width_; }
    int height() const { return height_; }
    void setNearest(bool nearest);
    void update(const uint8_t* rgba);  // same size: replaces the pixels (video frames)

    static int maxSize();

private:
    unsigned int id_ = 0;
    int width_;
    int height_;
    bool nearest_ = false;
};
