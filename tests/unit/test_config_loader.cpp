// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The roe Authors

#include "roe/features.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>

TEST_CASE("config file parses the documented TOML subset", "[config]")
{
    const std::string path = "roe_test_config.toml";
    {
        std::ofstream out(path);
        out << "# roe config\n";
        out << "[output]\n";
        out << "color = false\n";
        out << "show_bytes = true\n";
        out << "source = true\n";
        out << "pager = false  # inline comment\n";
        out << "syntax = \"att\"\n";
    }
    setenv("ROE_CONFIG", path.c_str(), 1);
    const roe::features::Config config = roe::features::load_config();
    CHECK_FALSE(config.color);
    CHECK(config.show_bytes);
    CHECK(config.source);
    CHECK_FALSE(config.pager);
    CHECK(config.syntax == "att");
    unsetenv("ROE_CONFIG");
    std::remove(path.c_str());
}

TEST_CASE("config_path honors ROE_CONFIG", "[config]")
{
    setenv("ROE_CONFIG", "/custom/roe.toml", 1);
    CHECK(roe::features::config_path() == std::filesystem::path("/custom/roe.toml"));
    unsetenv("ROE_CONFIG");
}
