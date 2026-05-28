// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
#pragma once

// roe's test suite uses Catch2 v3. CMake provides Catch2 via find_package or, as a
// fallback, FetchContent, and links each test against Catch2::Catch2WithMain.
#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include <sys/wait.h>

// Shared helpers for the subprocess-style integration tests (watch, pager,
// cross-arch). Header-only and inline so each test translation unit links its
// own copy without ODR clashes.
namespace roe_test {

struct CommandResult {
    int exit_code{1};
    std::string output; // merged stdout + stderr
};

inline CommandResult run_command(const std::string& command)
{
    std::array<char, 4096> buffer{};
    std::string output;
    FILE* pipe = popen((command + " 2>&1").c_str(), "r");
    if (pipe == nullptr) {
        return {127, "popen failed"};
    }
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        output += buffer.data();
    }
    const int status = pclose(pipe);
    if (status == -1) {
        return {127, output + "pclose failed"};
    }
    if (WIFEXITED(status)) {
        return {WEXITSTATUS(status), output};
    }
    return {128, output};
}

inline std::filesystem::path roe_executable()
{
    const std::vector<std::filesystem::path> candidates{
        std::filesystem::current_path() / "roe",
        std::filesystem::current_path() / "src" / "roe"};
    for (const std::filesystem::path& candidate : candidates) {
        if (std::filesystem::exists(candidate)) {
            return candidate;
        }
    }
    return {};
}

inline std::filesystem::path repo_root_from(const char* file)
{
    std::filesystem::path cursor = std::filesystem::absolute(file).parent_path();
    while (!cursor.empty() && cursor != cursor.root_path()) {
        if (std::filesystem::exists(cursor / "include" / "roe")) {
            return cursor;
        }
        cursor = cursor.parent_path();
    }
    return {};
}

inline std::string shell_quote(const std::string& text)
{
    std::string quoted = "'";
    for (const char character : text) {
        if (character == '\'') {
            quoted += "'\\''";
        } else {
            quoted += character;
        }
    }
    quoted += "'";
    return quoted;
}

inline bool contains(const std::string& haystack, const std::string& needle)
{
    return haystack.find(needle) != std::string::npos;
}

} // namespace roe_test
