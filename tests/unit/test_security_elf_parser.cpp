// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "roe/elf.hpp"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <vector>

#if __has_include(<catch2/catch_test_macros.hpp>)
#include <catch2/catch_test_macros.hpp>
#define ROE_SECURITY_ELF_USE_CATCH 1
#else
#define ROE_SECURITY_ELF_USE_CATCH 0
#endif

namespace {

std::vector<std::uint8_t> fuzzer_section_header_assertion_regression()
{
    return {
        0x7fU, 0x45U, 0x4cU, 0x46U, 0x01U, 0x02U, 0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x06U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U, 0x00U, 0x03U, 0x00U, 0x00U, 0x00U, 0x01U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x34U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x34U, 0x00U, 0xdfU, 0x46U, 0x01U, 0x00U, 0x03U,
        0x00U, 0x00U, 0x00U, 0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x34U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x34U, 0x00U, 0xe2U,
        0x46U, 0x01U, 0x02U, 0x01U, 0x00U, 0x00U, 0x00U, 0x02U, 0x01U, 0x85U, 0x00U, 0x00U,
        0x00U,
    };
}

bool test_security_elf_truncated_section_header_returns_error()
{
    auto parsed = roe::elf::parse_bytes(
        "fuzzer-section-header-assertion",
        fuzzer_section_header_assertion_regression());
    return !parsed && parsed.error().code == roe::ErrorCode::MalformedInput;
}

} // namespace

#if ROE_SECURITY_ELF_USE_CATCH
TEST_CASE("test_security_elf_truncated_section_header_returns_error")
{
    REQUIRE(test_security_elf_truncated_section_header_returns_error());
}
#else
int main()
{
    if (!test_security_elf_truncated_section_header_returns_error()) {
        std::cerr << "test_security_elf_truncated_section_header_returns_error failed\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
#endif
