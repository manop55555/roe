// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The roe Authors

#include "roe/elf.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <vector>

namespace {

void set16(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint16_t value)
{
    bytes[offset] = static_cast<std::uint8_t>(value & 0xffU);
    bytes[offset + 1] = static_cast<std::uint8_t>((value >> 8U) & 0xffU);
}

void set64(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint64_t value)
{
    for (std::size_t i = 0; i < 8; ++i) {
        bytes[offset + i] = static_cast<std::uint8_t>((value >> (8U * i)) & 0xffU);
    }
}

// A minimal, valid 64-byte little-endian ELF64 executable header with no sections
// or segments. Tests mutate individual fields to drive each rejection path.
std::vector<std::uint8_t> valid_elf64()
{
    std::vector<std::uint8_t> bytes(64, 0);
    bytes[0] = 0x7f;
    bytes[1] = 'E';
    bytes[2] = 'L';
    bytes[3] = 'F';
    bytes[4] = 2; // ELFCLASS64
    bytes[5] = 1; // ELFDATA2LSB
    bytes[6] = 1; // EV_CURRENT
    set16(bytes, 16, 2);  // e_type = ET_EXEC
    set16(bytes, 18, 62); // e_machine = x86-64
    bytes[20] = 1;        // e_version
    set16(bytes, 52, 64); // e_ehsize
    return bytes;
}

} // namespace

TEST_CASE("a minimal ELF64 header parses", "[elf][errors]")
{
    REQUIRE(roe::elf::parse_bytes("min", valid_elf64()).has_value());
}

TEST_CASE("truncated input is rejected", "[elf][errors]")
{
    const auto result = roe::elf::parse_bytes("trunc", {0x7f, 'E', 'L', 'F', 2, 1, 1, 0});
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == roe::ErrorCode::MalformedInput);
}

TEST_CASE("non-ELF magic is rejected as unsupported", "[elf][errors]")
{
    auto bytes = valid_elf64();
    bytes[1] = 'X';
    const auto result = roe::elf::parse_bytes("bad", std::move(bytes));
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == roe::ErrorCode::UnsupportedFormat);
}

TEST_CASE("invalid class, endianness, and version are rejected", "[elf][errors]")
{
    SECTION("class") {
        auto bytes = valid_elf64();
        bytes[4] = 9;
        CHECK_FALSE(roe::elf::parse_bytes("c", std::move(bytes)).has_value());
    }
    SECTION("endianness") {
        auto bytes = valid_elf64();
        bytes[5] = 9;
        CHECK_FALSE(roe::elf::parse_bytes("e", std::move(bytes)).has_value());
    }
    SECTION("ident version") {
        auto bytes = valid_elf64();
        bytes[6] = 9;
        CHECK_FALSE(roe::elf::parse_bytes("v", std::move(bytes)).has_value());
    }
}

TEST_CASE("an undersized header size is rejected", "[elf][errors]")
{
    auto bytes = valid_elf64();
    set16(bytes, 52, 10); // e_ehsize < 64
    CHECK_FALSE(roe::elf::parse_bytes("h", std::move(bytes)).has_value());
}

TEST_CASE("a section table that runs past the file is rejected", "[elf][errors]")
{
    auto bytes = valid_elf64();
    set64(bytes, 40, 0x10000);   // e_shoff far past EOF
    set16(bytes, 58, 64);        // e_shentsize
    set16(bytes, 60, 4);         // e_shnum
    CHECK_FALSE(roe::elf::parse_bytes("s", std::move(bytes)).has_value());
}

TEST_CASE("a program table that runs past the file is rejected", "[elf][errors]")
{
    auto bytes = valid_elf64();
    set64(bytes, 32, 0x10000);   // e_phoff far past EOF
    set16(bytes, 54, 56);        // e_phentsize
    set16(bytes, 56, 4);         // e_phnum
    CHECK_FALSE(roe::elf::parse_bytes("p", std::move(bytes)).has_value());
}

TEST_CASE("a too-small section entry size is rejected", "[elf][errors]")
{
    auto bytes = valid_elf64();
    set64(bytes, 40, 64);  // e_shoff right after header
    set16(bytes, 58, 8);   // e_shentsize too small for ELF64
    set16(bytes, 60, 1);   // e_shnum
    CHECK_FALSE(roe::elf::parse_bytes("se", std::move(bytes)).has_value());
}
