// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The roe Authors

#include "roe/watcher.hpp"

#include <chrono>
#include <string>
#include <thread>

#include <sys/stat.h>

#if defined(__linux__)
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <sys/inotify.h>
#include <unistd.h>
#include <vector>
#endif

namespace roe::watcher {
namespace {

Error make_error(ErrorCode code, std::string message)
{
    return Error{code, std::move(message), 0, false};
}

// A change signature combining mtime, size, and inode so that in-place edits and
// atomic replace-by-rename are both detected by the polling backend.
bool file_signature(const std::filesystem::path& path, std::uint64_t& signature)
{
    struct stat status {};
    if (::stat(path.c_str(), &status) != 0) {
        return false;
    }
    signature = static_cast<std::uint64_t>(status.st_mtime) ^
                (static_cast<std::uint64_t>(status.st_size) << 1U) ^
                (static_cast<std::uint64_t>(status.st_ino) << 2U);
    return true;
}

[[noreturn]] void poll_loop(const std::filesystem::path& path, const Options& options, const Callback& callback)
{
    const std::chrono::milliseconds interval =
        options.debounce.count() > 0 ? options.debounce : std::chrono::milliseconds(200);
    std::uint64_t last = 0;
    file_signature(path, last);
    while (true) {
        std::this_thread::sleep_for(interval);
        std::uint64_t current = 0;
        if (file_signature(path, current) && current != last) {
            last = current;
            callback(Event{path, EventKind::Modified});
        }
    }
}

} // namespace

Result<void> watch_file(const std::filesystem::path& path, const Options& options, Callback callback)
{
    if (path.empty()) {
        return Result<void>::err(make_error(ErrorCode::Usage, "watch path is empty"));
    }
    if (options.run_immediately) {
        callback(Event{path, EventKind::Modified});
    }

#if defined(__linux__)
    const int fd = inotify_init1(IN_CLOEXEC);
    if (fd >= 0) {
        const std::filesystem::path directory = path.has_parent_path() ? path.parent_path() : std::filesystem::path(".");
        const std::string filename = path.filename().string();
        const int wd = inotify_add_watch(
            fd, directory.c_str(), IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE | IN_DELETE_SELF | IN_MOVE_SELF);
        if (wd >= 0) {
            alignas(alignof(struct inotify_event)) char buffer[4096];
            while (true) {
                const ssize_t count = ::read(fd, buffer, sizeof(buffer));
                if (count <= 0) {
                    if (count < 0 && errno == EINTR) {
                        continue;
                    }
                    break;
                }
                bool changed = false;
                ssize_t offset = 0;
                while (offset < count) {
                    const auto* event = reinterpret_cast<const struct inotify_event*>(buffer + offset);
                    if (event->len == 0 || filename == event->name) {
                        changed = true;
                    }
                    offset += static_cast<ssize_t>(sizeof(struct inotify_event) + event->len);
                }
                if (changed) {
                    std::this_thread::sleep_for(options.debounce);
                    callback(Event{path, EventKind::Modified});
                }
            }
            ::close(fd);
            return Result<void>::ok();
        }
        ::close(fd);
    }
#endif

    poll_loop(path, options, callback);
}

} // namespace roe::watcher
