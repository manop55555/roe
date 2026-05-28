// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "roe/cli.hpp"
#include "roe/features.hpp"

#include <iostream>
#include <sstream>

int main(int argc, char** argv)
{
    const roe::Result<roe::cli::Arguments> parsed = roe::cli::parse_args(argc, argv);

    // Watch mode redraws repeatedly; stream it live instead of buffering for the pager.
    if (parsed.has_value() && parsed.value().watch) {
        return roe::cli::main_entry(argc, argv, std::cout, std::cerr);
    }

    std::ostringstream buffer;
    const int code = roe::cli::main_entry(argc, argv, buffer, std::cerr);

    const bool allow_pager =
        parsed.has_value() && !parsed.value().no_pager && roe::features::load_config().pager;
    roe::features::write_output(buffer.str(), allow_pager);
    return code;
}
