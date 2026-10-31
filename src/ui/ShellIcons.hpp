#pragma once
#include <map>
#include <memory>
#include <string>
#include "imgui.h"
#include "core/TreeNode.hpp"
#include "image/Texture.hpp"

// Windows default (shell) file icons - the exact same icons Explorer shows.
// On Windows, icons are pulled from the shell with SHGetFileInfoW
// (SHGFI_USEFILEATTRIBUTES: the file does not have to exist, the icon is
// resolved from the file extension's registered association) and uploaded as
// GL textures. Results are cached per extension: every file type is extracted
// exactly once for the lifetime of the app - nothing is drawn or queried per
// frame. On other platforms iconFor() returns 0 and the explorer falls back
// to its built-in drawn icons.
class ShellIcons {
public:
    static ShellIcons& instance();

    // ImGui texture id of the node's default shell icon, or 0 when
    // unavailable (non-Windows builds, extraction failure, no association).
    // 'apkRoot' selects the .apk association icon for the APK root node.
    ImTextureID iconFor(const TreeNode& node, bool apkRoot);

private:
    ShellIcons() = default;
    ~ShellIcons() = default;

#ifdef _WIN32
    ImTextureID textureFor(const std::string& key, const wchar_t* probeName, unsigned fileAttrs);
    std::map<std::string, std::unique_ptr<Texture>> cache_;
    ImTextureID folder_ = 0;
    ImTextureID generic_ = 0;
    ImTextureID apk_ = 0;
#endif
};
