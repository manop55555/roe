// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "roe/binary.hpp"
#include "roe/debug.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

TEST_CASE("DWARF line info maps the fixture's addresses to source", "[debug]")
{
    const auto loaded = roe::binary::load_file(ROE_FIXTURE_ELF);
    REQUIRE(loaded.has_value());

    const auto map = roe::debug::load_source_map(*loaded.value(), 0);
    REQUIRE(map.has_value());
    CHECK(map.value().format == roe::debug::Format::Dwarf);
    CHECK_FALSE(map.value().locations.empty());

    const auto compute = roe::binary::find_symbol(loaded.value()->view(), 0, "compute");
    REQUIRE(compute.has_value());

    const auto location = roe::debug::source_at(map.value(), compute->address);
    REQUIRE(location.has_value());
    CHECK(location->line > 0);
    CHECK(location->path.find("sample.c") != std::string::npos);
}

TEST_CASE("DWARF 4 line info is also decoded", "[debug]")
{
    const auto loaded = roe::binary::load_file(ROE_FIXTURE_ELF_V4);
    REQUIRE(loaded.has_value());
    const auto map = roe::debug::load_source_map(*loaded.value(), 0);
    REQUIRE(map.has_value());
    CHECK(map.value().format == roe::debug::Format::Dwarf);
    CHECK_FALSE(map.value().locations.empty());

    const auto compute = roe::binary::find_symbol(loaded.value()->view(), 0, "compute");
    REQUIRE(compute.has_value());
    const auto location = roe::debug::source_at(map.value(), compute->address);
    REQUIRE(location.has_value());
    CHECK(location->path.find("sample.c") != std::string::npos);
}

TEST_CASE("source_at returns nothing for an empty map", "[debug]")
{
    const roe::debug::SourceMap empty;
    CHECK_FALSE(roe::debug::source_at(empty, 0x1000).has_value());
}

TEST_CASE("a binary without debug info yields a fallback message", "[debug]")
{
    const auto loaded = roe::binary::load_file(ROE_FIXTURE_NODEBUG);
    REQUIRE(loaded.has_value());
    const auto map = roe::debug::load_source_map(*loaded.value(), 0);
    REQUIRE(map.has_value());
    CHECK_FALSE(map.value().fallback_message.empty());
}

TEST_CASE("interleave attaches source to instructions", "[debug]")
{
    const auto loaded = roe::binary::load_file(ROE_FIXTURE_ELF);
    REQUIRE(loaded.has_value());
    const auto map = roe::debug::load_source_map(*loaded.value(), 0);
    REQUIRE(map.has_value());

    const auto compute = roe::binary::find_symbol(loaded.value()->view(), 0, "compute");
    REQUIRE(compute.has_value());

    std::vector<roe::disasm::Instruction> instructions(1);
    instructions[0].address = compute->address;
    const auto interleaved = roe::debug::interleave(map.value(), instructions);
    REQUIRE(interleaved.size() == 1);
    CHECK(interleaved[0].source.has_value());
}
