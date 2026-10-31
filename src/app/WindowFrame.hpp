#pragma once
#include <memory>
#include <vector>

struct GLFWwindow;

struct Rect {
    float left = 0.f;
    float top = 0.f;
    float right = 0.f;
    float bottom = 0.f;

    bool contains(float x, float y) const { return x >= left && x < right && y >= top && y < bottom; }
};

struct FrameLayout {
    float titleBarHeight = 0.f;
    Rect systemMenu;
    Rect maximizeButton;
    std::vector<Rect> clientRects;
};

class WindowFrame {
public:
    explicit WindowFrame(GLFWwindow* window);
    ~WindowFrame();
    WindowFrame(const WindowFrame&) = delete;
    WindowFrame& operator=(const WindowFrame&) = delete;

    static bool isSupported();

    bool active() const { return impl_ != nullptr; }
    bool maximized() const;
    void minimize();
    void toggleMaximize();
    void close();

    void updateLayout(const FrameLayout& layout);
    bool maximizeHovered() const;
    bool maximizePressed() const;

private:
    struct Impl;
    GLFWwindow* window_;
    std::unique_ptr<Impl> impl_;
};
