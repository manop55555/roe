// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The roe Authors
#pragma once

/**
 * @file cli.hpp
 * @brief Public command line parsing and workflow entry points.
 */

#include "roe/core.hpp"

#include <cstdint>
#include <filesystem>
#include <iosfwd>
#include <optional>
#include <string>

namespace roe::cli {

/**
 * @brief Top-level CLI action selected from argv.
 */
enum class Action {
    ShowHelp,
    ShowVersion,
    ShowCompletions,
    ListFunctions,
    DisassembleSymbol,
    DisassembleSection,
    DisassembleAll,
    DisassembleAddr,
    DisassembleRange,
    RawBytes,
    ShowXrefs,
    ShowStats,
    ShowHeaders,
    ShowSections,
    ShowSegments,
    ShowImports,
    ShowExports,
    ShowHex,
    ShowStrings,
    ShowFind,
    ShowDiff,
    Watch
};

/**
 * @brief Parsed command line arguments.
 */
struct Arguments {
    Action action{Action::ShowHelp};
    std::optional<std::filesystem::path> file;
    std::optional<std::string> symbol;
    std::optional<std::string> section;
    std::optional<std::string> help_topic;
    std::optional<std::string> completions_shell;
    std::optional<std::string> grep_pattern;
    std::optional<std::string> calls_symbol;
    std::optional<std::string> contains_string;
    std::optional<std::string> xref_symbol;
    std::optional<std::string> arch;
    std::optional<std::string> find_pattern;
    std::optional<std::string> hex_section;
    std::optional<std::filesystem::path> diff_other;
    std::optional<std::uint64_t> addr;
    std::optional<std::uint64_t> range_start;
    std::optional<std::uint64_t> range_end;
    std::optional<std::uint64_t> bytes_count;
    std::optional<std::uint64_t> base;
    std::optional<std::uint64_t> min_len;
    bool no_color{false};
    bool no_pager{false};
    bool json{false};
    bool show_bytes{false};
    bool source{false};
    bool all_sections{false};
    bool stats{false};
    bool watch{false};
    bool headers{false};
    bool sections{false};
    bool segments{false};
    bool imports{false};
    bool exports{false};
    bool hex{false};
    bool strings{false};
    bool raw_bytes{false};
    bool hex_input{false};
    bool quiet{false};
    int verbose{0};
};

inline constexpr int exit_ok = 0;
inline constexpr int exit_usage = 1;
inline constexpr int exit_file_error = 2;
inline constexpr int exit_disasm_error = 3;

/**
 * @brief Parse command line arguments without doing IO.
 */
Result<Arguments> parse_args(int argc, char** argv);

/**
 * @brief Execute a parsed command and write output streams.
 */
int run(const Arguments& args, std::ostream& out, std::ostream& err);

/**
 * @brief Testable replacement for main().
 */
int main_entry(int argc, char** argv, std::ostream& out, std::ostream& err);

} // namespace roe::cli
