// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "roe/features.hpp"

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>

#include <sys/ioctl.h>
#include <unistd.h>

namespace roe::features {
namespace {

std::size_t count_lines(const std::string& text) noexcept
{
    std::size_t lines = 0;
    for (const char character : text) {
        if (character == '\n') {
            ++lines;
        }
    }
    return lines;
}

std::size_t terminal_rows() noexcept
{
    struct winsize size {};
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &size) == 0 && size.ws_row > 0) {
        return static_cast<std::size_t>(size.ws_row);
    }
    return 24;
}

bool should_page(const std::string& text, bool allow_pager) noexcept
{
    if (!allow_pager) {
        return false;
    }
    if (isatty(STDOUT_FILENO) == 0) {
        return false;
    }
    if (const char* no_pager = std::getenv("NO_PAGER"); no_pager != nullptr && no_pager[0] != '\0') {
        return false;
    }
    return count_lines(text) >= terminal_rows();
}

} // namespace

void write_output(const std::string& text, bool allow_pager)
{
    if (should_page(text, allow_pager)) {
        const char* pager_env = std::getenv("PAGER");
        const std::string pager = (pager_env != nullptr && pager_env[0] != '\0') ? pager_env : "less -R";
        FILE* pipe = popen(pager.c_str(), "w");
        if (pipe != nullptr) {
            std::fwrite(text.data(), 1, text.size(), pipe);
            pclose(pipe);
            return;
        }
    }
    std::cout << text;
    std::cout.flush();
}

} // namespace roe::features
