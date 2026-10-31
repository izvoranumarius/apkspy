#pragma once
#include "document/Document.hpp"

class ImageViewer {
public:
    void drawToolbar(Document& doc);
    void drawCanvas(Document& doc);

private:
    static float fitScale(const Texture& tex, ImVec2 view);
    static void drawChecker(ImDrawList* dl, ImVec2 min, ImVec2 max);
    static std::string formatSize(size_t bytes);
};
