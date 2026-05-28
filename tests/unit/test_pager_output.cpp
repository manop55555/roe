// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The roe Authors

#include "roe/features.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
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

// Pipe safety: even when paging is *allowed*, long output must go straight to
// stdout rather than spawning a pager that could block a pipeline. NO_PAGER is
// forced on so the assertion holds whether or not the test runs on a terminal.
TEST_CASE("write_output does not page long output when NO_PAGER is set", "[pager]")
{
    std::string long_text;
    for (int line = 0; line < 500; ++line) {
        long_text += "instruction line ";
        long_text += std::to_string(line);
        long_text += '\n';
    }

    setenv("NO_PAGER", "1", 1);
    std::ostringstream capture;
    std::streambuf* original = std::cout.rdbuf(capture.rdbuf());
    roe::features::write_output(long_text, true);
    std::cout.rdbuf(original);
    unsetenv("NO_PAGER");

    CHECK(capture.str() == long_text);
}
