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

TEST_CASE("the PE parser reads COFF function symbols by name", "[pe]")
{
    if (std::string(ROE_FIXTURE_PE).empty()) {
        SUCCEED("mingw PE toolchain unavailable; skipping");
        return;
    }
    const auto loaded = roe::binary::load_file(ROE_FIXTURE_PE);
    REQUIRE(loaded.has_value());
    const roe::binary::FileView& view = loaded.value()->view();

    // The function list is populated from the COFF symbol table (was empty before).
    const std::vector<roe::binary::Symbol> functions = roe::binary::function_symbols(view, 0);
    CHECK_FALSE(functions.empty());

    // 'main' is locatable by name with a real, section-backed address.
    const std::optional<roe::binary::Symbol> main_symbol = roe::binary::find_symbol(view, 0, "main");
    REQUIRE(main_symbol.has_value());
    CHECK(main_symbol->type == roe::binary::SymbolType::Function);
    CHECK(main_symbol->defined);
    CHECK(main_symbol->address != 0);
}

TEST_CASE("PE exported functions gain addresses from the COFF table", "[pe]")
{
    if (std::string(ROE_FIXTURE_PE_DLL).empty()) {
        SUCCEED("mingw PE toolchain unavailable; skipping");
        return;
    }
    const auto loaded = roe::binary::load_file(ROE_FIXTURE_PE_DLL);
    REQUIRE(loaded.has_value());
    bool roe_add_has_address = false;
    for (const roe::binary::Symbol& symbol : loaded.value()->view().objects.front().symbols) {
        if (symbol.bind == roe::binary::SymbolBind::Exported && symbol.name == "roe_add") {
            roe_add_has_address = symbol.address != 0; // filled from the COFF symbol, not left at 0
        }
    }
    CHECK(roe_add_has_address);
}

TEST_CASE("the PE parser rejects malformed input", "[pe]")
{
    CHECK_FALSE(roe::pe::parse_bytes("x", {'M', 'Z'}).has_value()); // too small
    std::vector<std::uint8_t> no_signature(0x80, 0);
    no_signature[0] = 'M';
    no_signature[1] = 'Z';
    CHECK_FALSE(roe::pe::parse_bytes("x", std::move(no_signature)).has_value()); // no PE signature
}

TEST_CASE("the PE parser bounds an implausible export-name count", "[pe][security]")
{
    // A well-formed PE32+ DLL that claims 1,000,000 export names. The parser must
    // reject the implausible count (kMaxParsedSymbols == 65536) up front instead
    // of walking it: a hostile file could otherwise force pathologically slow
    // parsing. Found by libFuzzer (pe_parser_fuzzer ran >70 min on such mutants).
    std::vector<std::uint8_t> buf(0x400, 0);
    auto put16 = [&buf](std::size_t off, std::uint16_t v) {
        buf[off] = static_cast<std::uint8_t>(v & 0xFFU);
        buf[off + 1] = static_cast<std::uint8_t>((v >> 8) & 0xFFU);
    };
    auto put32 = [&buf](std::size_t off, std::uint32_t v) {
        buf[off] = static_cast<std::uint8_t>(v & 0xFFU);
        buf[off + 1] = static_cast<std::uint8_t>((v >> 8) & 0xFFU);
        buf[off + 2] = static_cast<std::uint8_t>((v >> 16) & 0xFFU);
        buf[off + 3] = static_cast<std::uint8_t>((v >> 24) & 0xFFU);
    };

    buf[0] = 'M';
    buf[1] = 'Z';
    put32(0x3C, 0x40); // e_lfanew -> PE header at 0x40
    buf[0x40] = 'P';
    buf[0x41] = 'E'; // "PE\0\0" signature

    // COFF header at 0x44.
    put16(0x44, 0x8664); // machine: x86-64
    put16(0x46, 1); // one section
    put16(0x54, 0xF0); // size of optional header (PE32+, 16 data dirs)
    put16(0x56, 0x2000); // characteristics: DLL

    // Optional header (PE32+) at 0x58.
    put16(0x58, 0x20B); // magic: PE32+
    put32(0x58 + 108, 16); // NumberOfRvaAndSizes

    // Data directory 0 (export) at datadir_off = 0x58 + 112 = 0xC8.
    put32(0xC8, 0x1000); // export directory RVA
    put32(0xCC, 0x100); // export directory size

    // Section table at 0x58 + 0xF0 = 0x148; RVA 0x1000 -> file offset 0x200.
    const char* const name = ".rdata";
    for (std::size_t i = 0; name[i] != '\0'; ++i) {
        buf[0x148 + i] = static_cast<std::uint8_t>(name[i]);
    }
    put32(0x148 + 8, 0x1000); // virtual size
    put32(0x148 + 12, 0x1000); // virtual address
    put32(0x148 + 16, 0x200); // size of raw data
    put32(0x148 + 20, 0x200); // pointer to raw data
    put32(0x148 + 36, 0x40000040U); // initialized data | readable

    // Export directory at file offset 0x200.
    put32(0x200 + 24, 1000000U); // NumberOfNames: implausible
    put32(0x200 + 32, 0x1100); // AddressOfNames RVA (valid, within the section)

    const auto parsed = roe::pe::parse_bytes("crafted.dll", std::move(buf));
    REQUIRE(parsed.has_value()); // a well-formed PE, just with a hostile count
    std::size_t exported = 0;
    for (const roe::binary::Symbol& symbol : parsed.value().view.objects.front().symbols) {
        if (symbol.bind == roe::binary::SymbolBind::Exported) {
            ++exported;
        }
    }
    CHECK(exported == 0); // the count is rejected, not walked
    // This crafted PE has no COFF symbol table; the parser must mark it stripped and
    // fall back to the export table rather than reading a bogus symbol table.
    CHECK(parsed.value().view.objects.front().stripped);
}
