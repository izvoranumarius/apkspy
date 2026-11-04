CXX ?= g++
CC ?= gcc
BUILD := build
OBJ := $(BUILD)/obj
TARGET := $(BUILD)/apkspy
TEST := $(BUILD)/apkspy_core_test
PLATFORM_TEST := $(BUILD)/apkspy_platform_test
IMGUI_TEST := $(BUILD)/imgui_editor_test
LIB := lib

UNAME := $(shell uname -s)

# include/ and lib/ hold only external dependencies (one folder per library);
# the project's own headers live next to their sources in src/.
# On Linux/macOS GLFW comes from the system (pkg-config); the bundled headers
# in include/glfw are for the MSVC build.
INCLUDES := -Isrc -Iinclude -Iinclude/imgui -Iinclude/imgui/backends \
            -Iinclude/miniz -Iinclude/libwebp -Iinclude/glfw
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -Wno-unused-parameter $(INCLUDES) $(shell pkg-config --cflags glfw3 2>/dev/null)
CFLAGS := -O2 -w $(INCLUDES)
LDLIBS := $(shell pkg-config --libs glfw3 2>/dev/null) -lpthread

ifeq ($(UNAME),Darwin)
LDLIBS += -framework OpenGL
else
LDLIBS += -lGL
endif

APP_SRC := $(shell find src -name '*.cpp')
IMGUI_SRC := $(LIB)/imgui/imgui.cpp $(LIB)/imgui/imgui_draw.cpp $(LIB)/imgui/imgui_tables.cpp \
             $(LIB)/imgui/imgui_widgets.cpp $(LIB)/imgui/backends/imgui_impl_glfw.cpp \
             $(LIB)/imgui/backends/imgui_impl_opengl3.cpp
C_SRC := $(wildcard $(LIB)/miniz/*.c) $(wildcard $(LIB)/libwebp/src/dec/*.c) \
         $(wildcard $(LIB)/libwebp/src/dsp/*.c) $(wildcard $(LIB)/libwebp/src/utils/*.c)

# Headless tests link the core (no GLFW/OpenGL needed): everything except
# the UI panels, the app shell and the GL-backed image code; Texture and
# ImageDecoder are stubbed inside the test.
UI_SRC := src/app/Application.cpp src/app/Theme.cpp src/app/WindowFrame.cpp src/app/main.cpp \
          src/ui/EditorPanel.cpp src/ui/ExplorerPanel.cpp src/ui/OutputPanel.cpp src/ui/SearchPanel.cpp \
          src/ui/SettingsDialog.cpp src/ui/TitleBar.cpp src/ui/FileBrowser.cpp src/ui/ImageViewer.cpp \
          src/ui/OverviewPanel.cpp src/ui/AnalysisPanel.cpp src/ui/AnalysisNative.cpp src/ui/BookmarksPanel.cpp src/ui/GraphView.cpp src/ui/ScriptPanel.cpp src/ui/DevicePanels.cpp src/ui/McpSettings.cpp src/ui/TrafficPanel.cpp \
          src/ui/ShellIcons.cpp src/image/Texture.cpp src/image/ImageDecoder.cpp src/app/HeadlessMcp.cpp
CORE_SRC := $(filter-out $(UI_SRC),$(APP_SRC))

# miniz must be compiled as C (gcc), not C++.
MINIZ_SRC := lib/miniz/miniz.c lib/miniz/miniz_tinfl.c lib/miniz/miniz_tdef.c lib/miniz/miniz_zip.c
MINIZ_OBJ := $(patsubst lib/miniz/%.c,$(BUILD)/test_%.o,$(MINIZ_SRC))

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

test: $(TEST) $(PLATFORM_TEST) $(IMGUI_TEST)
	./$(TEST)
	./$(PLATFORM_TEST)
	./$(IMGUI_TEST)

$(BUILD)/test_%.o: lib/miniz/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST): tests/apkspy_core_test.cpp $(CORE_SRC) $(MINIZ_OBJ) $(wildcard src/*.hpp src/*/*.hpp)
	@mkdir -p $(@D)
	$(CXX) -std=c++17 -O1 -g -Wall -Wextra -Wno-unused-parameter $(INCLUDES) \
            tests/apkspy_core_test.cpp $(CORE_SRC) $(MINIZ_OBJ) \
            -o $@ -lpthread

# Portable suite (analysis engine, MCP server, device tooling); also built on
# Windows by tests/ApkSpyTests.vcxproj.
$(PLATFORM_TEST): tests/apkspy_platform_test.cpp $(CORE_SRC) $(MINIZ_OBJ) $(wildcard src/*/*.hpp)
	@mkdir -p $(@D)
	$(CXX) -std=c++17 -O1 -g -Wall -Wextra -Wno-unused-parameter $(INCLUDES) \
            tests/apkspy_platform_test.cpp $(CORE_SRC) $(MINIZ_OBJ) \
            -o $@ -lpthread

$(IMGUI_TEST): tests/imgui_editor_test.cpp $(LIB)/imgui/imgui.cpp $(LIB)/imgui/imgui_draw.cpp \
                 $(LIB)/imgui/imgui_tables.cpp $(LIB)/imgui/imgui_widgets.cpp
	@mkdir -p $(@D)
	$(CXX) -std=c++17 -O1 -Wall -Wextra -Wno-unused-parameter -Iinclude/imgui -Iinclude/imgui/backends \
	    tests/imgui_editor_test.cpp $(LIB)/imgui/imgui.cpp $(LIB)/imgui/imgui_draw.cpp \
	    $(LIB)/imgui/imgui_tables.cpp $(LIB)/imgui/imgui_widgets.cpp -o $@

run: $(TARGET)
	./$(TARGET)

clean:
	rm -rf $(BUILD)

-include $(DEPS)
