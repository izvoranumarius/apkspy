#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <windowsx.h>
#include <dwmapi.h>
#include <shellapi.h>
#endif

#include "app/WindowFrame.hpp"
#include <GLFW/glfw3.h>

#ifdef _WIN32
#define GLFW_EXPOSE_NATIVE_WIN32
#include <GLFW/glfw3native.h>

namespace {
constexpr wchar_t kProp[] = L"ApkSpyWindowFrame";
constexpr int kResizeBorder = 5;
}

struct WindowFrame::Impl {
    HWND hwnd = nullptr;
    WNDPROC original = nullptr;
    FrameLayout layout;
    bool maxHover = false;
    bool maxPressed = false;
    bool tracking = false;

    static LRESULT CALLBACK proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);
    LRESULT handle(UINT msg, WPARAM wp, LPARAM lp);
    LRESULT hitTest(LPARAM lp) const;
    void calcSize(NCCALCSIZE_PARAMS* params) const;
    static bool taskbarAutoHide();
};

LRESULT CALLBACK WindowFrame::Impl::proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    auto* self = static_cast<Impl*>(GetPropW(hwnd, kProp));
    if (!self) return DefWindowProcW(hwnd, msg, wp, lp);
    return self->handle(msg, wp, lp);
}

LRESULT WindowFrame::Impl::handle(UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_NCCALCSIZE:
        if (wp) calcSize(reinterpret_cast<NCCALCSIZE_PARAMS*>(lp));
        return 0;
    case WM_NCHITTEST:
        return hitTest(lp);
    case WM_NCACTIVATE:
        return DefWindowProcW(hwnd, msg, wp, -1);
    case WM_NCMOUSEMOVE:
        maxHover = wp == HTMAXBUTTON;
        if (maxHover && !tracking) {
            TRACKMOUSEEVENT track = {sizeof(track), TME_LEAVE | TME_NONCLIENT, hwnd, 0};
            TrackMouseEvent(&track);
            tracking = true;
        }
        break;
    case WM_NCMOUSELEAVE:
        maxHover = false;
        maxPressed = false;
        tracking = false;
        break;
    case WM_MOUSEMOVE:
        maxHover = false;
        break;
    case WM_NCLBUTTONDOWN:
        if (wp == HTMAXBUTTON) {
            maxPressed = true;
            return 0;
        }
        break;
    case WM_NCLBUTTONUP:
        if (wp == HTMAXBUTTON && maxPressed) {
            maxPressed = false;
            ShowWindow(hwnd, IsZoomed(hwnd) ? SW_RESTORE : SW_MAXIMIZE);
            return 0;
        }
        maxPressed = false;
        break;
    case WM_LBUTTONUP:
        maxPressed = false;
        break;
    default:
        break;
    }
    return CallWindowProcW(original, hwnd, msg, wp, lp);
}

LRESULT WindowFrame::Impl::hitTest(LPARAM lp) const {
    POINT pt = {GET_X_LPARAM(lp), GET_Y_LPARAM(lp)};
    ScreenToClient(hwnd, &pt);
    RECT rc = {};
    GetClientRect(hwnd, &rc);
    const float x = (float)pt.x;
    const float y = (float)pt.y;

    bool interactive = layout.maximizeButton.contains(x, y);
    for (const Rect& r : layout.clientRects) {
        if (r.contains(x, y)) {
            interactive = true;
            break;
        }
    }

    if (!IsZoomed(hwnd)) {
        const int border = MulDiv(kResizeBorder, (int)GetDpiForWindow(hwnd), 96);
        const bool left = pt.x < border;
        const bool right = pt.x >= rc.right - border;
        bool top = pt.y < border;
        const bool bottom = pt.y >= rc.bottom - border;
        if (top && interactive) top = false;
        if (top && left) return HTTOPLEFT;
        if (top && right) return HTTOPRIGHT;
        if (bottom && left) return HTBOTTOMLEFT;
        if (bottom && right) return HTBOTTOMRIGHT;
        if (left) return HTLEFT;
        if (right) return HTRIGHT;
        if (top) return HTTOP;
        if (bottom) return HTBOTTOM;
    }

    if (layout.titleBarHeight > 0.f && y < layout.titleBarHeight) {
        if (layout.maximizeButton.contains(x, y)) return HTMAXBUTTON;
        if (layout.systemMenu.contains(x, y)) return HTSYSMENU;
        if (interactive) return HTCLIENT;
        return HTCAPTION;
    }
    return HTCLIENT;
}

bool WindowFrame::Impl::taskbarAutoHide() {
    APPBARDATA data = {};
    data.cbSize = sizeof(data);
    return (SHAppBarMessage(ABM_GETSTATE, &data) & ABS_AUTOHIDE) != 0;
}

void WindowFrame::Impl::calcSize(NCCALCSIZE_PARAMS* params) const {
    if (!IsZoomed(hwnd)) return;
    const UINT dpi = GetDpiForWindow(hwnd);
    const int padding = GetSystemMetricsForDpi(SM_CXPADDEDBORDER, dpi);
    const int fx = GetSystemMetricsForDpi(SM_CXFRAME, dpi) + padding;
    const int fy = GetSystemMetricsForDpi(SM_CYFRAME, dpi) + padding;
    RECT& r = params->rgrc[0];
    r.left += fx;
    r.right -= fx;
    r.top += fy;
    r.bottom -= fy;
    if (taskbarAutoHide()) r.bottom -= 1;
}
#else
struct WindowFrame::Impl {};
#endif

WindowFrame::WindowFrame(GLFWwindow* window) : window_(window) {
#ifdef _WIN32
    HWND hwnd = glfwGetWin32Window(window);
    if (!hwnd) return;
    auto impl = std::make_unique<Impl>();
    impl->hwnd = hwnd;
    SetPropW(hwnd, kProp, impl.get());
    impl->original = reinterpret_cast<WNDPROC>(
        SetWindowLongPtrW(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&Impl::proc)));
    MARGINS margins = {1, 1, 1, 1};
    DwmExtendFrameIntoClientArea(hwnd, &margins);
    SetWindowPos(hwnd, nullptr, 0, 0, 0, 0,
                 SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    impl_ = std::move(impl);
#endif
}

WindowFrame::~WindowFrame() {
#ifdef _WIN32
    if (!impl_) return;
    SetWindowLongPtrW(impl_->hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(impl_->original));
    RemovePropW(impl_->hwnd, kProp);
#endif
}

bool WindowFrame::isSupported() {
#ifdef _WIN32
    return true;
#else
    return false;
#endif
}

bool WindowFrame::maximized() const { return glfwGetWindowAttrib(window_, GLFW_MAXIMIZED) == GLFW_TRUE; }

void WindowFrame::minimize() { glfwIconifyWindow(window_); }

void WindowFrame::toggleMaximize() {
    if (maximized()) glfwRestoreWindow(window_);
    else glfwMaximizeWindow(window_);
}

void WindowFrame::close() { glfwSetWindowShouldClose(window_, GLFW_TRUE); }

void WindowFrame::updateLayout(const FrameLayout& layout) {
#ifdef _WIN32
    if (impl_) impl_->layout = layout;
#else
    (void)layout;
#endif
}

bool WindowFrame::maximizeHovered() const {
#ifdef _WIN32
    return impl_ && impl_->maxHover;
#else
    return false;
#endif
}

bool WindowFrame::maximizePressed() const {
#ifdef _WIN32
    return impl_ && impl_->maxPressed;
#else
    return false;
#endif
}
