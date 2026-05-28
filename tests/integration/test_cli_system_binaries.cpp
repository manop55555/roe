// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "../test_support.hpp"

#include <array>
#include <cstdio>
#include <filesystem>
#include <string>
#include <sys/wait.h>
#include <vector>

namespace {

struct CommandResult {
    int exit_code{1};
    std::string output;
};

std::string shell_quote(const std::filesystem::path& path)
{
    const std::string text = path.string();
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

CommandResult run_command(const std::string& command)
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

std::filesystem::path roe_executable()
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

bool contains(const std::string& text, const std::string& needle)
{
    return text.find(needle) != std::string::npos;
}

} // namespace

TEST_CASE("test_cli_system_binaries_list_functions_without_crashing", "[integration]")
{
    const std::filesystem::path roe = roe_executable();
    if (roe.empty()) {
        return;
    }

    const std::vector<std::filesystem::path> binaries{
        "/usr/bin/ls",
        "/usr/bin/ssh",
        "/usr/bin/python3"};

    bool tested_any = false;
    for (const std::filesystem::path& binary : binaries) {
        if (!std::filesystem::exists(binary)) {
            continue;
        }
        tested_any = true;
        const CommandResult result = run_command(shell_quote(roe) + " " + shell_quote(binary) + " --no-color");
        REQUIRE(result.exit_code == 0);
        CHECK(!contains(result.output, "\x1b["));
    }

    REQUIRE(tested_any);
}

