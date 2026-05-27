#pragma once

/**
 * @file cli.hpp
 * @brief Public command line parsing and workflow entry points.
 */

#include "roe/core.hpp"

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
    ShowXrefs,
    ShowStats,
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
    bool no_color{false};
    bool no_pager{false};
    bool json{false};
    bool show_bytes{false};
    bool source{false};
    bool all_sections{false};
    bool stats{false};
    bool watch{false};
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
