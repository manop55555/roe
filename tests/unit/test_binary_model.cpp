// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

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

TEST_CASE("load_bytes reports a detected-but-unparsed format honestly", "[binary]")
{
    // ELF, Mach-O, and PE are parsed; static archives are detected but not parsed.
    const roe::Result<std::unique_ptr<BinaryFile>> result =
        load_bytes("lib.a", {'!', '<', 'a', 'r', 'c', 'h', '>', '\n', 0, 0});
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == roe::ErrorCode::UnsupportedFormat);
    CHECK(result.error().message.find("archive") != std::string::npos);
}

TEST_CASE("load_bytes reports unknown formats with a hex dump", "[binary]")
{
    const roe::Result<std::unique_ptr<BinaryFile>> result = load_bytes("blob", {0x01, 0x02, 0x03, 0x04});
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().message.find("01 02 03 04") != std::string::npos);
}

TEST_CASE("binary helpers handle empty and missing inputs", "[binary]")
{
    const FileView empty;
    CHECK_FALSE(primary_object(empty).has_value());
    CHECK_FALSE(find_section(empty, 0, ".text").has_value());
    CHECK(function_symbols(empty, 0).empty());
    CHECK_FALSE(find_symbol(empty, 5, "x").has_value());

    for (const Architecture arch : {Architecture::Unknown, Architecture::X86, Architecture::X86_64,
             Architecture::Arm, Architecture::ArmThumb, Architecture::AArch64, Architecture::RiscV32,
             Architecture::RiscV64, Architecture::Mips32, Architecture::Mips32el, Architecture::Mips64,
             Architecture::Mips64el, Architecture::PowerPc32, Architecture::PowerPc64, Architecture::PowerPc64le}) {
        CHECK_FALSE(architecture_name(arch).empty());
    }
    for (const Format format : {Format::Unknown, Format::Elf, Format::MachO, Format::MachOFat,
             Format::PeCoff, Format::Archive}) {
        CHECK_FALSE(format_name(format).empty());
    }
    CHECK(architecture_name(Architecture::PowerPc64le) == "ppc64le");
    CHECK(format_name(Format::Archive) == "static archive");

    const auto missing = load_file("/nonexistent/roe/file");
    REQUIRE_FALSE(missing.has_value());
    CHECK(missing.error().code == roe::ErrorCode::FileIo);
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
