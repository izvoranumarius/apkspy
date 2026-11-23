CXX ?= g++
CC ?= gcc
BUILD := build
OBJ := $(BUILD)/obj
TARGET := $(BUILD)/apkspy
TEST := $(BUILD)/apkspy_core_test
PLATFORM_TEST := $(BUILD)/apkspy_platform_test
IMGUI_TEST := $(BUILD)/imgui_editor_test
SMALI_TEST := $(BUILD)/smali_validate_test
EDITS_TEST := $(BUILD)/edits_test
INSIGHTS_TEST := $(BUILD)/insights_test
LIB := lib

UNAME := $(shell uname -s)

# include/ and lib/ hold only external dependencies (one folder per library);
# the project's own headers live next to their sources in src/.
# On Linux/macOS GLFW comes from the system (pkg-config); the bundled headers
# in include/glfw are for the MSVC build.
INCLUDES := -Isrc -Iinclude -Iinclude/imgui -Iinclude/imgui/backends \
            -Iinclude/miniz -Iinclude/libwebp -Iinclude/glfw -Iinclude/mbedtls \
            -Iinclude/brotli -Iinclude/zstd
CXXFLAGS := -std=c++23 -O2 -Wall -Wextra -Wno-unused-parameter $(INCLUDES) $(shell pkg-config --cflags glfw3 2>/dev/null)
CFLAGS := -O2 -w -DZSTD_DISABLE_ASM -DZSTD_MULTITHREAD=0 $(INCLUDES)
LDLIBS := $(shell pkg-config --libs glfw3 2>/dev/null) -lpthread -lm
# miniaudio loads the platform audio libraries at run time.
ifneq ($(UNAME),Darwin)
LDLIBS += -ldl -lutil
endif

ifeq ($(UNAME),Darwin)
LDLIBS += -framework OpenGL
else
LDLIBS += -lGL
endif

APP_SRC := $(shell find src -name '*.cpp')
IMGUI_SRC := $(LIB)/imgui/imgui.cpp $(LIB)/imgui/imgui_draw.cpp $(LIB)/imgui/imgui_tables.cpp \
             $(LIB)/imgui/imgui_widgets.cpp $(LIB)/imgui/backends/imgui_impl_glfw.cpp \
             $(LIB)/imgui/backends/imgui_impl_opengl3.cpp
DECOMP_SRC := $(wildcard lib/brotli/common/*.c) $(wildcard lib/brotli/dec/*.c) \
              $(wildcard lib/zstd/common/*.c) $(wildcard lib/zstd/decompress/*.c)
C_SRC := $(wildcard $(LIB)/miniz/*.c) $(wildcard $(LIB)/libwebp/src/dec/*.c) \
         $(wildcard $(LIB)/libwebp/src/dsp/*.c) $(wildcard $(LIB)/libwebp/src/utils/*.c) \
         $(filter-out $(LIB)/mbedtls/net_sockets.c,$(wildcard $(LIB)/mbedtls/*.c)) \
         $(DECOMP_SRC)

# Headless tests link the core (no GLFW/OpenGL needed): everything except
# the UI panels, the app shell and the GL-backed image code; Texture and
# ImageDecoder are stubbed inside the test.
UI_SRC := src/app/Application.cpp src/app/Theme.cpp src/app/ThemePresets.cpp src/app/WindowFrame.cpp src/app/main.cpp \
          src/ui/EditorPanel.cpp src/ui/ExplorerPanel.cpp src/ui/OutputPanel.cpp src/ui/SearchPanel.cpp \
          src/ui/SettingsDialog.cpp src/ui/TitleBar.cpp src/ui/FileBrowser.cpp src/ui/ImageViewer.cpp \
          src/ui/OverviewPanel.cpp src/ui/AnalysisPanel.cpp src/ui/AnalysisNative.cpp src/ui/AnalysisDecompiler.cpp src/ui/BehaviorPanel.cpp src/ui/DiffPanel.cpp src/ui/SecurityPanel.cpp src/ui/DependenciesPanel.cpp src/ui/BookmarksPanel.cpp src/ui/EditsPanel.cpp src/ui/InsightsPanel.cpp src/ui/FridaPanel.cpp src/ui/RepackPanel.cpp src/ui/GraphView.cpp src/ui/ScriptPanel.cpp src/ui/DevicePanels.cpp src/ui/McpSettings.cpp src/ui/TrafficPanel.cpp src/ui/TrafficRepeater.cpp src/ui/TrafficIntercept.cpp src/ui/TrafficRules.cpp src/ui/TrafficComparer.cpp src/ui/TrafficHistory.cpp src/ui/TrafficCerts.cpp src/ui/TrafficTools.cpp src/ui/TrafficRouting.cpp \
          src/ui/ShellIcons.cpp src/ui/HexView.cpp src/ui/AudioPlayer.cpp src/ui/AudioCodecs.cpp src/ui/VideoPlayer.cpp src/ui/MediaViews.cpp src/ui/TerminalPanel.cpp src/ui/DecoderPanel.cpp src/ui/CommandPalette.cpp src/core/Pty.cpp src/image/Texture.cpp src/image/ImageDecoder.cpp src/app/HeadlessMcp.cpp
CORE_SRC := $(filter-out $(UI_SRC),$(APP_SRC))

# miniz and mbedTLS must be compiled as C (gcc), not C++. mbedTLS's own
# network layer is excluded: the proxy runs TLS over its own Socket class.
MINIZ_SRC := lib/miniz/miniz.c lib/miniz/miniz_tinfl.c lib/miniz/miniz_tdef.c lib/miniz/miniz_zip.c
MINIZ_OBJ := $(patsubst lib/miniz/%.c,$(BUILD)/test_%.o,$(MINIZ_SRC))
MBEDTLS_SRC := $(filter-out lib/mbedtls/net_sockets.c,$(wildcard lib/mbedtls/*.c))
MBEDTLS_OBJ := $(patsubst lib/mbedtls/%.c,$(BUILD)/test_mbedtls_%.o,$(MBEDTLS_SRC))
# Body decoders (decompression only): brotli and zstd.
DECOMP_OBJ := $(patsubst lib/%.c,$(BUILD)/test_decomp/%.o,$(DECOMP_SRC))

CXX_OBJ := $(patsubst %.cpp,$(OBJ)/%.o,$(APP_SRC) $(IMGUI_SRC))
C_OBJ := $(patsubst %.c,$(OBJ)/%.o,$(C_SRC))
DEPS := $(CXX_OBJ:.o=.d)

.PHONY: all run test clean

all: $(TARGET)

$(TARGET): $(CXX_OBJ) $(C_OBJ)
	@mkdir -p $(@D)
	$(CXX) $^ -o $@ $(LDLIBS)

$(OBJ)/%.o: %.cpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@

$(OBJ)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

test: $(TEST) $(PLATFORM_TEST) $(IMGUI_TEST) $(SMALI_TEST) $(EDITS_TEST) $(INSIGHTS_TEST)
	./$(TEST)
	./$(PLATFORM_TEST)
	./$(IMGUI_TEST)
	./$(SMALI_TEST)
	./$(EDITS_TEST)
	./$(INSIGHTS_TEST)

$(BUILD)/test_%.o: lib/miniz/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_decomp/%.o: lib/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_mbedtls_%.o: lib/mbedtls/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -Iinclude/mbedtls -Ilib/mbedtls -c $< -o $@

$(TEST): tests/apkspy_core_test.cpp $(CORE_SRC) $(MINIZ_OBJ) $(MBEDTLS_OBJ) $(DECOMP_OBJ) $(wildcard src/*.hpp src/*/*.hpp)
	@mkdir -p $(@D)
	$(CXX) -std=c++23 -O1 -g -Wall -Wextra -Wno-unused-parameter $(INCLUDES) \
            tests/apkspy_core_test.cpp $(CORE_SRC) $(MINIZ_OBJ) $(MBEDTLS_OBJ) $(DECOMP_OBJ) \
            -o $@ -lpthread

# Portable suite (analysis engine, MCP server, device tooling); also built on
# Windows by tests/ApkSpyTests.vcxproj.
$(PLATFORM_TEST): tests/apkspy_platform_test.cpp $(CORE_SRC) $(MINIZ_OBJ) $(MBEDTLS_OBJ) $(DECOMP_OBJ) $(wildcard src/*/*.hpp)
	@mkdir -p $(@D)
	$(CXX) -std=c++23 -O1 -g -Wall -Wextra -Wno-unused-parameter $(INCLUDES) \
            tests/apkspy_platform_test.cpp $(CORE_SRC) $(MINIZ_OBJ) $(MBEDTLS_OBJ) $(DECOMP_OBJ) \
            -o $@ -lpthread

$(IMGUI_TEST): tests/imgui_editor_test.cpp $(LIB)/imgui/imgui.cpp $(LIB)/imgui/imgui_draw.cpp \
                 $(LIB)/imgui/imgui_tables.cpp $(LIB)/imgui/imgui_widgets.cpp
	@mkdir -p $(@D)
	$(CXX) -std=c++23 -O1 -Wall -Wextra -Wno-unused-parameter -Iinclude/imgui -Iinclude/imgui/backends \
	    tests/imgui_editor_test.cpp $(LIB)/imgui/imgui.cpp $(LIB)/imgui/imgui_draw.cpp \
	    $(LIB)/imgui/imgui_tables.cpp $(LIB)/imgui/imgui_widgets.cpp -o $@

# Smali edit validation (pure: no APK, no file system).
$(SMALI_TEST): tests/smali_validate_test.cpp src/smali/Validate.cpp src/analysis/DexFile.cpp \
                src/smali/Validate.hpp src/analysis/DexFile.hpp
	@mkdir -p $(@D)
	$(CXX) -std=c++23 -O1 -g -Wall -Wextra -Wno-unused-parameter -Isrc \
	    tests/smali_validate_test.cpp src/smali/Validate.cpp src/analysis/DexFile.cpp -o $@

$(EDITS_TEST): tests/edits_test.cpp src/edit/Edits.cpp src/smali/Validate.cpp src/analysis/DexFile.cpp \
               src/edit/Edits.hpp src/smali/Validate.hpp src/core/SafePath.hpp
	@mkdir -p $(@D)
	$(CXX) -std=c++23 -O1 -g -Wall -Wextra -Wno-unused-parameter -Isrc \
	    tests/edits_test.cpp src/edit/Edits.cpp src/smali/Validate.cpp src/analysis/DexFile.cpp -o $@

$(INSIGHTS_TEST): tests/insights_test.cpp src/analysis/Insights.cpp src/analysis/Mapping.cpp src/analysis/NetSecConfig.cpp \
                  src/analysis/Insights.hpp src/analysis/Mapping.hpp
	@mkdir -p $(@D)
	$(CXX) -std=c++23 -O1 -g -Wall -Wextra -Wno-unused-parameter -Isrc \
	    tests/insights_test.cpp src/analysis/Insights.cpp src/analysis/Mapping.cpp src/analysis/NetSecConfig.cpp -o $@

run: $(TARGET)
	./$(TARGET)

clean:
	rm -rf $(BUILD)

-include $(DEPS)
