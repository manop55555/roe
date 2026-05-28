// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The roe Authors

#include "roe/binary.hpp"
#include "roe/pe.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cctype>
#include <cstdint>
#include <string>
#include <vector>

namespace {
std::string lower(std::string text)
{
    for (char& c : text) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return text;
}
} // namespace

TEST_CASE("the PE parser reads imports grouped by DLL", "[pe]")
{
    if (std::string(ROE_FIXTURE_PE).empty()) {
        SUCCEED("mingw PE toolchain unavailable; skipping");
        return;
    }
    const auto loaded = roe::binary::load_file(ROE_FIXTURE_PE);
    REQUIRE(loaded.has_value());
    const roe::binary::FileView& view = loaded.value()->view();
    CHECK(view.format == roe::binary::Format::PeCoff);
    const roe::binary::Object& object = view.objects.front();
    CHECK(object.architecture == roe::binary::Architecture::X86_64);

    bool known_dll = false;
    for (const std::string& library : object.libraries) {
        const std::string l = lower(library);
        if (l.find("kernel32") != std::string::npos || l.find("msvcrt") != std::string::npos) {
            known_dll = true;
        }
    }
    CHECK(known_dll);

    bool import_with_library = false;
    for (const roe::binary::Symbol& symbol : object.symbols) {
        if (symbol.bind == roe::binary::SymbolBind::Imported && !symbol.library.empty()) {
            import_with_library = true;
        }
    }
    CHECK(import_with_library);
}

TEST_CASE("the PE parser reads DLL exports", "[pe]")
{
    if (std::string(ROE_FIXTURE_PE_DLL).empty()) {
        SUCCEED("mingw PE toolchain unavailable; skipping");
        return;
    }
    const auto loaded = roe::binary::load_file(ROE_FIXTURE_PE_DLL);
    REQUIRE(loaded.has_value());
    const roe::binary::Object& object = loaded.value()->view().objects.front();
    bool has_add = false;
    bool has_mul = false;
    for (const roe::binary::Symbol& symbol : object.symbols) {
        if (symbol.bind == roe::binary::SymbolBind::Exported) {
            if (symbol.name == "roe_add") {
                has_add = true;
            }
            if (symbol.name == "roe_mul") {
                has_mul = true;
            }
        }
    }
    CHECK(has_add);
    CHECK(has_mul);
}

TEST_CASE("the PE parser rejects malformed input", "[pe]")
{
    CHECK_FALSE(roe::pe::parse_bytes("x", {'M', 'Z'}).has_value()); // too small
    std::vector<std::uint8_t> no_signature(0x80, 0);
    no_signature[0] = 'M';
    no_signature[1] = 'Z';
    CHECK_FALSE(roe::pe::parse_bytes("x", std::move(no_signature)).has_value()); // no PE signature
}
