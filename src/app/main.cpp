#include <cstdio>
#include <exception>
#include "app/Application.hpp"

int main() {
    try {
        Application app;
        return app.run();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "%s\n", e.what());
        return 1;
    }
}
