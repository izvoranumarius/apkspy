CXX ?= g++
CC ?= gcc
BUILD := build
OBJ := $(BUILD)/obj
TARGET := $(BUILD)/apkspy
LIB := lib

UNAME := $(shell uname -s)

# include/ and lib/ hold only external dependencies (one folder per library);
# the project's own headers live next to their sources in src/.
# On Linux/macOS GLFW comes from the system (pkg-config); the bundled headers
# in include/glfw are for the MSVC build.
INCLUDES := -Isrc -Iinclude -Iinclude/imgui -Iinclude/imgui/backends \
            -Iinclude/miniz -Iinclude/libwebp
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -Wno-unused-parameter $(INCLUDES) $(shell pkg-config --cflags glfw3)
CFLAGS := -O2 -w $(INCLUDES)
LDLIBS := $(shell pkg-config --libs glfw3) -lpthread

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

CXX_OBJ := $(patsubst %.cpp,$(OBJ)/%.o,$(APP_SRC) $(IMGUI_SRC))
C_OBJ := $(patsubst %.c,$(OBJ)/%.o,$(C_SRC))
DEPS := $(CXX_OBJ:.o=.d)

.PHONY: all run clean

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

run: $(TARGET)
        ./$(TARGET)

clean:
        rm -rf $(BUILD)

-include $(DEPS)
