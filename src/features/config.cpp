// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "roe/features.hpp"

#include <cstdlib>
#include <fstream>
#include <string>

namespace roe::features {
namespace {

std::string trim(const std::string& text)
{
    const auto first = text.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return {};
    }
    const auto last = text.find_last_not_of(" \t\r\n");
    return text.substr(first, last - first + 1);
}

std::string unquote(const std::string& value)
{
    if (value.size() >= 2 && (value.front() == '"' || value.front() == '\'') && value.back() == value.front()) {
        return value.substr(1, value.size() - 2);
    }
    return value;
}

bool as_bool(const std::string& value, bool fallback)
{
    const std::string text = unquote(value);
    if (text == "true" || text == "1" || text == "yes" || text == "on") {
        return true;
    }
    if (text == "false" || text == "0" || text == "no" || text == "off") {
        return false;
    }
    return fallback;
}

const char* env(const char* name)
{
    const char* value = std::getenv(name);
    return (value != nullptr && value[0] != '\0') ? value : nullptr;
}

} // namespace

std::filesystem::path config_path()
{
    if (const char* explicit_path = env("ROE_CONFIG")) {
        return std::filesystem::path(explicit_path);
    }
#if defined(__APPLE__)
    if (const char* home = env("HOME")) {
        return std::filesystem::path(home) / "Library" / "Application Support" / "roe" / "config.toml";
    }
#else
    if (const char* xdg = env("XDG_CONFIG_HOME")) {
        return std::filesystem::path(xdg) / "roe" / "config.toml";
    }
    if (const char* home = env("HOME")) {
        return std::filesystem::path(home) / ".config" / "roe" / "config.toml";
    }
#endif
    return {};
}

Config load_config()
{
    Config config;
    const std::filesystem::path path = config_path();
    if (path.empty()) {
        return config;
    }
    std::ifstream stream(path);
    if (!stream) {
        return config;
    }

    std::string line;
    while (std::getline(stream, line)) {
        const std::string trimmed = trim(line);
        if (trimmed.empty() || trimmed.front() == '#' || trimmed.front() == '[') {
            continue;
        }
        const auto equals = trimmed.find('=');
        if (equals == std::string::npos) {
            continue;
        }
        const std::string key = trim(trimmed.substr(0, equals));
        std::string value = trim(trimmed.substr(equals + 1));
        const auto comment = value.find(" #");
        if (comment != std::string::npos) {
            value = trim(value.substr(0, comment));
        }
        if (key == "color") {
            config.color = as_bool(value, config.color);
        } else if (key == "pager") {
            config.pager = as_bool(value, config.pager);
        } else if (key == "show_bytes") {
            config.show_bytes = as_bool(value, config.show_bytes);
        } else if (key == "source") {
            config.source = as_bool(value, config.source);
        } else if (key == "syntax") {
            config.syntax = unquote(value);
        }
    }
    return config;
}

} // namespace roe::features
