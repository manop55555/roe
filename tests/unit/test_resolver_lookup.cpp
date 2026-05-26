#if __has_include(<catch2/catch_test_macros.hpp>)
#include <catch2/catch_test_macros.hpp>
#define ROE_RESOLVER_HAS_CATCH 1
#else
#define ROE_RESOLVER_HAS_CATCH 0
#endif

#include "roe/resolver.hpp"

#include <cstdint>
#if !ROE_RESOLVER_HAS_CATCH
#include <iostream>
#endif
#include <string>
#include <utility>
#include <vector>

namespace {

roe::elf::Symbol make_symbol(
    std::string name,
    std::uint64_t address,
    std::uint64_t size,
    roe::elf::SymbolBind bind = roe::elf::SymbolBind::Global,
    bool dynamic = false) {
    roe::elf::Symbol symbol;
    symbol.name = std::move(name);
    symbol.address = address;
    symbol.size = size;
    symbol.section_index = 1;
    symbol.bind = bind;
    symbol.type = roe::elf::SymbolType::Function;
    symbol.defined = true;
    symbol.dynamic = dynamic;
    return symbol;
}

roe::elf::Relocation make_relocation(
    std::string section_name,
    std::uint64_t offset,
    std::uint32_t type,
    std::string symbol_name,
    std::int64_t addend,
    bool has_addend) {
    roe::elf::Relocation relocation;
    relocation.section_name = std::move(section_name);
    relocation.offset = offset;
    relocation.type = type;
    relocation.symbol_name = std::move(symbol_name);
    relocation.addend = addend;
    relocation.has_addend = has_addend;
    return relocation;
}

bool test_resolver_demangle_cpp_names() {
    const std::string raw = "_Z3fooi";
    const std::string resolved = roe::resolver::demangle(raw);
    return resolved == "foo(int)" || resolved == raw;
}

bool test_resolver_symbol_lookup() {
    roe::elf::File file;
    file.symbols.push_back(make_symbol("_Z3fooi", 0x1000U, 0x20U));
    file.symbols.push_back(make_symbol("bar", 0x1050U, 0x10U));
    file.symbols.push_back(make_symbol("local_impl", 0x1080U, 0x10U, roe::elf::SymbolBind::Local));

    const auto result = roe::resolver::build_index(file);
    if (!result) {
        return false;
    }

    const roe::resolver::Index& index = result.value();
    const auto exact = roe::resolver::symbol_at(index, 0x1000U);
    if (!exact || !exact->exact || exact->raw_name != "_Z3fooi") {
        return false;
    }

    const auto inside = roe::resolver::nearest_symbol(index, 0x1008U);
    if (!inside || inside->exact || inside->raw_name != "_Z3fooi") {
        return false;
    }

    const auto preceding = roe::resolver::nearest_symbol(index, 0x1040U);
    if (!preceding || preceding->raw_name != "_Z3fooi") {
        return false;
    }

    const auto missing = roe::resolver::nearest_symbol(index, 0x0FFFU);
    if (missing) {
        return false;
    }

    roe::resolver::Options options;
    options.include_local_symbols = false;
    const auto filtered = roe::resolver::build_index(file, options);
    if (!filtered) {
        return false;
    }

    return !roe::resolver::symbol_at(filtered.value(), 0x1080U).has_value();
}

bool test_resolver_relocation_lookup() {
    roe::elf::File file;
    file.symbols.push_back(make_symbol("_Z3fooi", 0x1000U, 0x20U));
    file.relocations.push_back(
        make_relocation(".rela.plt", 0x2005U, 7U, "_Z3fooi", -4, true));

    const auto result = roe::resolver::build_index(file);
    if (!result) {
        return false;
    }

    const auto reference = roe::resolver::relocation_at(result.value(), 0x2005U);
    if (!reference) {
        return false;
    }

    return reference->raw_name == "_Z3fooi" && reference->relocation_section == ".rela.plt" &&
           reference->relocation_type == 7U && reference->addend == -4 &&
           reference->has_addend && reference->name.find("@plt") != std::string::npos;
}

bool test_resolver_instruction_annotation() {
    roe::elf::File file;
    file.symbols.push_back(make_symbol("caller", 0x2000U, 0x20U));
    file.relocations.push_back(
        make_relocation(".rela.text", 0x2005U, 4U, "target_symbol", 0, false));

    const auto result = roe::resolver::build_index(file);
    if (!result) {
        return false;
    }

    std::vector<roe::disasm::Instruction> instructions;
    roe::disasm::Instruction first;
    first.address = 0x2000U;
    first.size = 5U;
    first.mnemonic = "push";
    first.operands = "rbp";
    instructions.push_back(first);

    roe::disasm::Instruction second;
    second.address = 0x2004U;
    second.size = 5U;
    second.mnemonic = "call";
    second.operands = "0";
    second.branch_kind = roe::disasm::BranchKind::Call;
    instructions.push_back(second);

    const auto annotated = roe::resolver::annotate(result.value(), instructions);
    if (annotated.size() != 2U) {
        return false;
    }

    return annotated[0].symbol.has_value() && !annotated[0].reference.has_value() &&
           annotated[1].symbol.has_value() && annotated[1].reference.has_value() &&
           annotated[1].reference->raw_name == "target_symbol";
}

} // namespace

#if ROE_RESOLVER_HAS_CATCH
TEST_CASE("test_resolver_demangle_cpp_names", "[resolver]") {
    REQUIRE(test_resolver_demangle_cpp_names());
}

TEST_CASE("test_resolver_symbol_lookup", "[resolver]") {
    REQUIRE(test_resolver_symbol_lookup());
}

TEST_CASE("test_resolver_relocation_lookup", "[resolver]") {
    REQUIRE(test_resolver_relocation_lookup());
}

TEST_CASE("test_resolver_instruction_annotation", "[resolver]") {
    REQUIRE(test_resolver_instruction_annotation());
}
#else
namespace {

bool run_all_tests() {
    return test_resolver_demangle_cpp_names() && test_resolver_symbol_lookup() &&
           test_resolver_relocation_lookup() && test_resolver_instruction_annotation();
}

} // namespace

int main() {
    if (!run_all_tests()) {
        std::cerr << "resolver tests failed\n";
        return 1;
    }
    return 0;
}
#endif
