#pragma once

/**
 * @file features.hpp
 * @brief Higher-level analysis features built on binary, disassembly, and resolver data.
 */

#include "roe/binary.hpp"
#include "roe/resolver.hpp"

#include <cstdint>
#include <regex>
#include <string>
#include <string_view>
#include <vector>

namespace roe::features {

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
