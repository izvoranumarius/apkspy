#pragma once
#include <cstdint>
#include <string>
#include <vector>

struct DecodedImage {
    int width = 0;
    int height = 0;
    std::string format;
    std::vector<uint8_t> rgba;
};

class ImageDecoder {
public:
    static bool decode(const std::vector<uint8_t>& bytes, DecodedImage& out, std::string& error);
    static std::string sniffFormat(const std::vector<uint8_t>& bytes);

private:
    static bool decodeWebp(const std::vector<uint8_t>& bytes, DecodedImage& out, std::string& error);
    static bool decodeStb(const std::vector<uint8_t>& bytes, DecodedImage& out, std::string& error);
};
