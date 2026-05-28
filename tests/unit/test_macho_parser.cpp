// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "roe/binary.hpp"
#include "roe/macho.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

TEST_CASE("the Mach-O parser reads architecture, symbols, imports, exports", "[macho]")
{
    if (std::string(ROE_FIXTURE_MACHO).empty()) {
        SUCCEED("clang Mach-O cross-target unavailable; skipping");
        return;
    }
    const auto loaded = roe::binary::load_file(ROE_FIXTURE_MACHO);
    REQUIRE(loaded.has_value());
    const roe::binary::FileView& view = loaded.value()->view();
    CHECK(view.format == roe::binary::Format::MachO);
    REQUIRE_FALSE(view.objects.empty());
    const roe::binary::Object& object = view.objects.front();
    CHECK(object.architecture == roe::binary::Architecture::AArch64);

    bool has_export = false;
    bool has_import = false;
    for (const roe::binary::Symbol& symbol : object.symbols) {
        if (symbol.bind == roe::binary::SymbolBind::Exported && (symbol.name == "my_export" || symbol.name == "my_helper")) {
            has_export = true;
        }
        if (symbol.bind == roe::binary::SymbolBind::Imported && symbol.name == "external_func") {
            has_import = true;
        }
    }
    CHECK(has_export);
    CHECK(has_import);

    const auto code = std::find_if(object.sections.begin(), object.sections.end(),
        [](const roe::binary::Section& s) { return s.executable; });
    REQUIRE(code != object.sections.end());
    const auto bytes = loaded.value()->section_bytes(*code);
    REQUIRE(bytes.has_value());
    CHECK_FALSE(bytes.value().bytes.empty());
}

TEST_CASE("a fat Mach-O container selects a slice", "[macho]")
{
    if (std::string(ROE_FIXTURE_MACHO).empty()) {
        SUCCEED("clang Mach-O cross-target unavailable; skipping");
        return;
    }
    std::ifstream stream(ROE_FIXTURE_MACHO, std::ios::binary);
    std::istreambuf_iterator<char> stream_begin(stream);
    const std::istreambuf_iterator<char> stream_end;
    const std::vector<std::uint8_t> thin(stream_begin, stream_end);
    REQUIRE_FALSE(thin.empty());

    std::vector<std::uint8_t> fat;
    const auto push_be32 = [&fat](std::uint32_t value) {
        fat.push_back(static_cast<std::uint8_t>((value >> 24) & 0xffU));
        fat.push_back(static_cast<std::uint8_t>((value >> 16) & 0xffU));
        fat.push_back(static_cast<std::uint8_t>((value >> 8) & 0xffU));
        fat.push_back(static_cast<std::uint8_t>(value & 0xffU));
    };
    constexpr std::uint32_t fat_magic = 0xcafebabeU;
    constexpr std::uint32_t cpu_arm64 = 0x0100000cU;
    constexpr std::uint32_t slice_offset = 4096U;
    push_be32(fat_magic);
    push_be32(1); // one architecture
    push_be32(cpu_arm64);
    push_be32(0);                                      // cpusubtype
    push_be32(slice_offset);                           // offset
    push_be32(static_cast<std::uint32_t>(thin.size())); // size
    push_be32(0);                                      // align
    fat.resize(slice_offset, 0);
    fat.insert(fat.end(), thin.begin(), thin.end());

    const auto parsed = roe::macho::parse_bytes("fat", std::move(fat));
    REQUIRE(parsed.has_value());
    REQUIRE_FALSE(parsed.value().view.objects.empty());
    CHECK(parsed.value().view.objects.front().architecture == roe::binary::Architecture::AArch64);
}

TEST_CASE("the Mach-O parser reads x86-64 objects", "[macho]")
{
    if (std::string(ROE_FIXTURE_MACHO_X64).empty()) {
        SUCCEED("clang x86_64 Mach-O cross-target unavailable; skipping");
        return;
    }
    const auto loaded = roe::binary::load_file(ROE_FIXTURE_MACHO_X64);
    REQUIRE(loaded.has_value());
    const roe::binary::Object& object = loaded.value()->view().objects.front();
    CHECK(object.architecture == roe::binary::Architecture::X86_64);
    bool has_export = false;
    for (const roe::binary::Symbol& symbol : object.symbols) {
        if (symbol.bind == roe::binary::SymbolBind::Exported && symbol.name == "my_export") {
            has_export = true;
        }
    }
    CHECK(has_export);
}

TEST_CASE("the Mach-O parser rejects malformed input", "[macho]")
{
    CHECK_FALSE(roe::macho::parse_bytes("x", {0xcf, 0xfa}).has_value());
    CHECK_FALSE(roe::macho::parse_bytes("x", {1, 2, 3, 4, 5, 6, 7, 8}).has_value());
    CHECK_FALSE(roe::macho::parse_bytes("x", {}).has_value());
}
