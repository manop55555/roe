// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The roe Authors

#include "roe/features.hpp"

#include <catch2/catch_test_macros.hpp>

#include <iostream>
#include <sstream>
#include <string>

TEST_CASE("write_output writes straight to stdout when paging is disabled", "[pager]")
{
    std::ostringstream capture;
    std::streambuf* original = std::cout.rdbuf(capture.rdbuf());
    roe::features::write_output("alpha\nbeta\n", false);
    std::cout.rdbuf(original);
    CHECK(capture.str() == "alpha\nbeta\n");
}
