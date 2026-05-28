// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "roe/disasm.hpp"
#include "roe/elf.hpp"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("the ELF-typed disassembly overloads work on the fixture", "[disasm][elf]")
{
    const auto file = roe::elf::parse_file(ROE_FIXTURE_ELF);
    REQUIRE(file.has_value());

    roe::disasm::Options options;
    options.architecture = roe::disasm::Architecture::X86_64;

    const auto compute = roe::elf::find_symbol(file.value(), "compute");
    REQUIRE(compute.has_value());
    const auto decoded = roe::disasm::disassemble_function(file.value(), compute.value(), options);
    REQUIRE(decoded.has_value());
    CHECK_FALSE(decoded.value().empty());

    const auto text = roe::elf::find_section(file.value(), ".text");
    REQUIRE(text.has_value());
    const auto section = roe::disasm::disassemble_section(file.value(), text.value(), options);
    REQUIRE(section.has_value());
    CHECK_FALSE(section.value().empty());
}

TEST_CASE("disassembling a non-executable section is rejected", "[disasm][elf]")
{
    const auto file = roe::elf::parse_file(ROE_FIXTURE_ELF);
    REQUIRE(file.has_value());
    roe::disasm::Options options;
    options.architecture = roe::disasm::Architecture::X86_64;

    const auto rodata = roe::elf::find_section(file.value(), ".rodata");
    if (rodata.has_value()) {
        const auto result = roe::disasm::disassemble_section(file.value(), rodata.value(), options);
        CHECK_FALSE(result.has_value());
    }
}
