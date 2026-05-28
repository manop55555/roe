// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
#pragma once

/**
 * @file watcher.hpp
 * @brief Platform-neutral file watcher abstraction for watch mode.
 */

#include "roe/core.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>

namespace roe::watcher {

enum class EventKind : std::uint8_t { Modified, Replaced, Deleted };

/**
 * @brief File change event delivered by the platform watcher backend.
 */
struct Event {
    std::filesystem::path path;
    EventKind kind{EventKind::Modified};
};

/**
 * @brief Watcher runtime options.
 */
struct Options {
    std::chrono::milliseconds debounce{100};
    bool run_immediately{true};
};

using Callback = std::function<void(const Event&)>;

namespace detail {

/**
 * @brief Update @p state and return true when the file's change signature
 *        (mtime, size, inode) differs from it. Exposed for testing.
 */
bool changed_since(const std::filesystem::path& path, std::uint64_t& state);

} // namespace detail

/**
 * @brief Watch one file and invoke the callback after changes.
 */
Result<void> watch_file(const std::filesystem::path& path, const Options& options, Callback callback);

} // namespace roe::watcher
