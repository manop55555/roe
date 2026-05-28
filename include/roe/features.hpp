// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
#pragma once

/**
 * @file features.hpp
 * @brief Higher-level analysis features built on binary, disassembly, and resolver data.
 */

#include "roe/binary.hpp"
#include "roe/resolver.hpp"

#include <cstdint>
#include <filesystem>
#include <regex>
#include <string>
#include <string_view>
#include <vector>

namespace roe::features {

/**
 * @brief Resolved configuration defaults (CLI flags always override these).
 */
struct Config {
    bool color{true};
    bool pager{true};
    bool show_bytes{false};
    bool source{false};
    std::string syntax{"intel"};
};

/**
 * @brief Resolve the configuration file path (ROE_CONFIG, then platform default).
 */
std::filesystem::path config_path();

/**
 * @brief Load configuration from the TOML config file; a missing file yields defaults.
 */
Config load_config();

/**
 * @brief Write text to stdout, paging through $PAGER when stdout is an interactive
 *        terminal, paging is allowed, and the text exceeds the terminal height.
 */
void write_output(const std::string& text, bool allow_pager);

/**
 * @brief Search and filter options from the CLI or config file.
 */
struct FilterOptions {
    std::string grep_pattern;
    std::string calls_symbol;
    std::string contains_string;
};

/**
 * @brief One cross-reference to a symbol or string.
 */
struct Xref {
    std::string from_function;
    std::uint64_t from_function_address{0};
    std::uint64_t instruction_address{0};
    std::string target_name;
    std::uint64_t target_address{0};
    std::string instruction_text;
};

/**
 * @brief Per-function control-flow summary.
 */
struct FunctionStats {
    std::string name;
    std::uint64_t address{0};
    std::uint64_t size{0};
    std::uint64_t basic_blocks{0};
    std::uint64_t branch_count{0};
    std::uint64_t max_nesting_depth{0};
};

/**
 * @brief Function plus decoded body used by analysis features.
 */
struct FunctionBody {
    binary::Symbol symbol;
    std::vector<resolver::AnnotatedInstruction> instructions;
};

/**
 * @brief A string literal and the instruction (if any) that references it.
 */
struct StringRef {
    std::uint64_t address{0};
    std::string value;
    std::string from_function;
    std::uint64_t from_address{0};
    bool referenced{false};
};

/**
 * @brief A symbol matched by --find, tagged with its source table.
 */
struct FindMatch {
    std::string name;
    std::uint64_t address{0};
    std::string source; // symtab | dynsym | import | export
};

/**
 * @brief Function-level difference between two binaries.
 */
struct DiffResult {
    std::vector<std::string> added;
    std::vector<std::string> removed;
    std::vector<std::string> changed;
    std::uint64_t unchanged{0};
};

/**
 * @brief Collect string literals (>= min_len) with their referencing instruction.
 */
std::vector<StringRef> find_string_references(
    const std::vector<binary::StringLiteral>& strings,
    const std::vector<FunctionBody>& functions,
    std::uint64_t min_len);

/**
 * @brief Compute the function-level diff between two function-body sets.
 */
DiffResult diff_functions(const std::vector<FunctionBody>& old_functions, const std::vector<FunctionBody>& new_functions);

/**
 * @brief Apply regex filtering to function symbols.
 */
Result<std::vector<binary::Symbol>> filter_functions(
    const std::vector<binary::Symbol>& functions,
    std::string_view regex_pattern);

/**
 * @brief List functions that call or branch to a named symbol.
 */
std::vector<binary::Symbol> functions_calling(
    const std::vector<FunctionBody>& functions,
    std::string_view symbol_name);

/**
 * @brief List functions whose annotated instructions reference a string literal.
 */
std::vector<binary::Symbol> functions_containing_string(
    const std::vector<FunctionBody>& functions,
    std::string_view text);

/**
 * @brief Compute cross-references to a named symbol or string.
 */
std::vector<Xref> find_xrefs(
    const std::vector<FunctionBody>& functions,
    std::string_view target_name);

/**
 * @brief Compute per-function statistics.
 */
std::vector<FunctionStats> compute_stats(const std::vector<FunctionBody>& functions);

/**
 * @brief Attach string-reference annotations to instructions.
 */
std::vector<resolver::AnnotatedInstruction> annotate_string_references(
    const binary::Object& object,
    const std::vector<resolver::AnnotatedInstruction>& instructions);

} // namespace roe::features
