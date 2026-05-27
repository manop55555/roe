// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The roe Authors

#include "roe/binary.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace roe::binary;

TEST_CASE("detect_format recognizes container magics", "[binary]")
{
    CHECK(detect_format({0x7f, 'E', 'L', 'F', 2, 1, 1, 0}) == Format::Elf);
    CHECK(detect_format({'!', '<', 'a', 'r', 'c', 'h', '>', '\n'}) == Format::Archive);
    CHECK(detect_format({'M', 'Z', 0x90, 0x00}) == Format::PeCoff);
    CHECK(detect_format({0xcf, 0xfa, 0xed, 0xfe}) == Format::MachO);
    CHECK(detect_format({0xfe, 0xed, 0xfa, 0xce}) == Format::MachO);
    CHECK(detect_format({0xca, 0xfe, 0xba, 0xbe}) == Format::MachOFat);
    CHECK(detect_format({0x01, 0x02, 0x03, 0x04}) == Format::Unknown);
    CHECK(detect_format({}) == Format::Unknown);
}

TEST_CASE("first_bytes_hex renders a hex preview", "[binary]")
{
    CHECK(first_bytes_hex({0x7f, 0x45, 0x4c, 0x46}) == "7f 45 4c 46");
    CHECK(first_bytes_hex({}) == "(empty)");
}

TEST_CASE("format and architecture names are stable", "[binary]")
{
    CHECK(format_name(Format::Elf) == "ELF");
    CHECK(format_name(Format::MachO) == "Mach-O");
    CHECK(format_name(Format::PeCoff) == "PE/COFF");
    CHECK(architecture_name(Architecture::X86_64) == "x86-64");
    CHECK(architecture_name(Architecture::AArch64) == "aarch64");
    CHECK(architecture_name(Architecture::RiscV64) == "riscv64");
}

TEST_CASE("load_bytes reports non-ELF formats honestly", "[binary]")
{
    const roe::Result<std::unique_ptr<BinaryFile>> result = load_bytes("stub.exe", {'M', 'Z', 0, 0, 0, 0});
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == roe::ErrorCode::UnsupportedFormat);
    CHECK(result.error().message.find("PE/COFF") != std::string::npos);
}

TEST_CASE("load_bytes reports unknown formats with a hex dump", "[binary]")
{
    const roe::Result<std::unique_ptr<BinaryFile>> result = load_bytes("blob", {0x01, 0x02, 0x03, 0x04});
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().message.find("01 02 03 04") != std::string::npos);
}

TEST_CASE("the ELF adapter normalizes the fixture", "[binary]")
{
    const roe::Result<std::unique_ptr<BinaryFile>> loaded = load_file(ROE_FIXTURE_ELF);
    REQUIRE(loaded.has_value());
    const FileView& view = loaded.value()->view();
    CHECK(view.format == Format::Elf);
    REQUIRE_FALSE(view.objects.empty());
    const Object& object = view.objects.front();
    CHECK(object.architecture == Architecture::X86_64);

    const std::optional<Symbol> compute = find_symbol(view, 0, "compute");
    REQUIRE(compute.has_value());
    CHECK(compute->type == SymbolType::Function);
    CHECK(compute->defined);

    CHECK(function_symbols(view, 0).size() >= 3);

    const std::optional<Section> text = find_section(view, 0, ".text");
    REQUIRE(text.has_value());
    CHECK(text->executable);

    const roe::Result<SectionBytes> bytes = loaded.value()->section_bytes(*text);
    REQUIRE(bytes.has_value());
    CHECK_FALSE(bytes.value().bytes.empty());

    bool found_string = false;
    for (const StringLiteral& literal : object.strings) {
        if (literal.value.find("roe sample result") != std::string::npos) {
            found_string = true;
        }
    }
    CHECK(found_string);
}
