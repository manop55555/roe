#pragma once

/**
 * @file format.hpp
 * @brief Public text, color, label, and JSON rendering interfaces.
 */

#include "roe/core.hpp"
#include "roe/elf.hpp"
#include "roe/resolver.hpp"

#include <string>
#include <vector>

namespace roe::format {

/**
 * @brief Formatting mode requested by the CLI.
 */
enum class Mode {
    Text,
    Json
};

/**
 * @brief Render options for user-visible output.
 */
struct Options {
    Mode mode{Mode::Text};
    bool color{true};
    bool no_color_env{false};
    bool preserve_addresses{true};
    bool show_bytes{false};
};

/**
 * @brief Return default formatting options.
 */
Options default_options();

/**
 * @brief Return whether ANSI color should be emitted.
 */
bool color_enabled(const Options& options) noexcept;

/**
 * @brief Render the program banner and version.
 */
Result<std::string> render_banner();

/**
 * @brief Render command line help text.
 */
Result<std::string> render_help();

/**
 * @brief Render an error for humans.
 */
Result<std::string> render_error(const Error& error, const Options& options);

/**
 * @brief Render a function symbol listing.
 */
Result<std::string> render_function_list(
    const elf::File& file,
    const resolver::Index& index,
    const Options& options);

/**
 * @brief Render annotated instructions as text.
 */
Result<std::string> render_disassembly(
    const std::vector<resolver::AnnotatedInstruction>& instructions,
    const Options& options);

/**
 * @brief Render annotated instructions as JSON.
 */
Result<std::string> render_json(
    const std::vector<resolver::AnnotatedInstruction>& instructions,
    const Options& options);

} // namespace roe::format
