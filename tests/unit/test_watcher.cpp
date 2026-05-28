// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "roe/watcher.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>

TEST_CASE("watch_file rejects an empty path", "[watcher]")
{
    const auto result = roe::watcher::watch_file("", {}, [](const roe::watcher::Event&) {});
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == roe::ErrorCode::Usage);
}

TEST_CASE("change detection tracks a file's signature", "[watcher]")
{
    const std::string path = "roe_watch_test.bin";
    {
        std::ofstream out(path);
        out << "one";
    }
    std::uint64_t state = 0;
    CHECK(roe::watcher::detail::changed_since(path, state));       // first observation differs from 0
    CHECK_FALSE(roe::watcher::detail::changed_since(path, state)); // unchanged
    {
        std::ofstream out(path);
        out << "two, with a different size";
    }
    CHECK(roe::watcher::detail::changed_since(path, state)); // size changed
    std::remove(path.c_str());

    std::uint64_t missing_state = 0;
    CHECK_FALSE(roe::watcher::detail::changed_since("/nonexistent/roe-watch", missing_state));
}
