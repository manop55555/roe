// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
#pragma once

/**
 * @file resolver.hpp
 * @brief Public symbol, relocation, and annotation interfaces.
 */

#include "roe/core.hpp"
#include "roe/binary.hpp"
#include "roe/disasm.hpp"
#include "roe/elf.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace roe::resolver {

/**
 * @brief Resolver behavior switches.
 */
struct Options {
    bool demangle_names{true};
    bool include_dynamic_symbols{true};
    bool include_local_symbols{true};
};

/**
 * @brief Symbol resolved for a concrete or nearest address.
 */
struct ResolvedSymbol {
    std::string name;
    std::string raw_name;
    std::uint64_t address{0};
    std::uint64_t size{0};
    bool exact{false};
    bool dynamic{false};
    std::size_t object_index{0};
    bool synthetic{false};
};

/**
 * @brief Relocation or PLT/GOT reference resolved at an address.
 */
struct ResolvedReference {
    std::uint64_t address{0};
    std::string name;
    std::string raw_name;
    std::string relocation_section;
    std::uint32_t relocation_type{0};
    std::int64_t addend{0};
    bool has_addend{false};
    std::size_t object_index{0};
};

/**
 * @brief Built lookup tables for one ELF file.
 */
struct Index {
    std::vector<ResolvedSymbol> symbols;
    std::vector<ResolvedReference> relocations;
    binary::Format format{binary::Format::Unknown};
    std::vector<binary::StringLiteral> strings;
};

/**
 * @brief Instruction plus symbol and relocation annotations.
 */
struct AnnotatedInstruction {
    disasm::Instruction instruction;
    std::optional<ResolvedSymbol> symbol;
    std::optional<ResolvedReference> reference;
    std::optional<ResolvedSymbol> branch_target_symbol;
    std::optional<binary::StringLiteral> string_reference;
    std::optional<std::string> source_text; ///< Source line text for --source, when available.
    std::uint32_t source_line{0};            ///< 1-based source line number, 0 if unknown.
    std::string source_path;                 ///< Source file path, empty if unknown.
};

/**
 * @brief Build a resolver index for a parsed ELF file.
 */
Result<Index> build_index(const elf::File& file, const Options& options = {});

/**
 * @brief Build a resolver index for any parsed binary format.
 */
Result<Index> build_index(const binary::BinaryFile& file, const Options& options = {});

/**
 * @brief Return a symbol that starts exactly at address.
 */
std::optional<ResolvedSymbol> symbol_at(const Index& index, std::uint64_t address);

/**
 * @brief Return the nearest containing or preceding symbol for address.
 */
std::optional<ResolvedSymbol> nearest_symbol(const Index& index, std::uint64_t address);

/**
 * @brief Return a relocation resolved for address, if present.
 */
std::optional<ResolvedReference> relocation_at(const Index& index, std::uint64_t address);

/**
 * @brief Attach symbol and relocation annotations to decoded instructions.
 */
std::vector<AnnotatedInstruction> annotate(
    const Index& index,
    const std::vector<disasm::Instruction>& instructions);

/**
 * @brief Demangle a C++ symbol name when possible, otherwise return input text.
 */
std::string demangle(std::string_view name);

} // namespace roe::resolver
