// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
#pragma once

/**
 * @file format.hpp
 * @brief Public text, color, label, and JSON rendering interfaces.
 */

#include "roe/core.hpp"
#include "roe/binary.hpp"
#include "roe/features.hpp"
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
    bool pager{true};
    bool preserve_addresses{true};
    bool show_bytes{false};
    bool source{false};
    bool quiet{false};
    int verbose{0};
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
 * @brief Render extended version information.
 */
Result<std::string> render_version();

/**
 * @brief Render command line help text.
 */
Result<std::string> render_help();

/**
 * @brief Render focused help for a supported topic.
 */
Result<std::string> render_help_topic(const std::string& topic);

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
 * @brief Render a function listing for any supported binary format.
 */
Result<std::string> render_function_list(
    const binary::FileView& file,
    const resolver::Index& index,
    const Options& options);

/**
 * @brief Render a heading and a table of the given function symbols.
 */
Result<std::string> render_function_table(
    std::string_view heading,
    const std::vector<binary::Symbol>& functions,
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

/**
 * @brief Render xrefs as text or JSON depending on options.
 */
Result<std::string> render_xrefs(const std::vector<features::Xref>& xrefs, const Options& options);

/**
 * @brief Render function statistics as text or JSON depending on options.
 */
Result<std::string> render_stats(const std::vector<features::FunctionStats>& stats, const Options& options);

/**
 * @brief Render section metadata as text or JSON depending on options.
 */
Result<std::string> render_sections(const binary::FileView& file, const Options& options);

/**
 * @brief Render the file header summary (format, architecture, type, entry).
 */
Result<std::string> render_headers(const binary::FileView& file, const Options& options);

/**
 * @brief Render loadable segments (ELF program headers / Mach-O segments / PE data dirs).
 */
Result<std::string> render_segments(const binary::FileView& file, const Options& options);

/**
 * @brief Render imported symbols grouped by their owning library where known.
 */
Result<std::string> render_imports(const binary::FileView& file, const Options& options);

/**
 * @brief Render exported symbols.
 */
Result<std::string> render_exports(const binary::FileView& file, const Options& options);

/**
 * @brief Generate a shell completion script for bash, zsh, fish, or PowerShell.
 */
Result<std::string> render_completions(const std::string& shell);

/**
 * @brief Render a hex + ASCII dump of bytes starting at a base address.
 */
Result<std::string> render_hex(const std::vector<std::uint8_t>& bytes, std::uint64_t base, const Options& options);

/**
 * @brief Render extracted strings with their referencing instruction.
 */
Result<std::string> render_strings(const std::vector<features::StringRef>& refs, const Options& options);

/**
 * @brief Render --find matches tagged by symbol source.
 */
Result<std::string> render_find(
    const std::vector<features::FindMatch>& matches, const std::string& pattern, const Options& options);

/**
 * @brief Render a function-level diff summary.
 */
Result<std::string> render_diff(const features::DiffResult& result, const Options& options);

} // namespace roe::format
