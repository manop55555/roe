#pragma once

/**
 * @file debug.hpp
 * @brief Source-level debug information interfaces for roe.
 */

#include "roe/binary.hpp"
#include "roe/disasm.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace roe::debug {

enum class Format : std::uint8_t { None, Dwarf, Pdb };

/**
 * @brief Source location for one machine address.
 */
struct SourceLocation {
    std::string path;
    std::uint32_t line{0};
    std::uint32_t column{0};
    std::string text;
};

/**
 * @brief Debug information index for one binary object.
 */
struct SourceMap {
    Format format{Format::None};
    std::size_t object_index{0};
    std::vector<std::pair<std::uint64_t, SourceLocation>> locations;
    std::string fallback_message;
};

/**
 * @brief Instruction with optional source line attached.
 */
struct SourceInstruction {
    disasm::Instruction instruction;
    std::optional<SourceLocation> source;
};

/**
 * @brief Load DWARF or PDB information for one parsed binary object.
 */
Result<SourceMap> load_source_map(const binary::BinaryFile& file, std::size_t object_index);

/**
 * @brief Return source information for an address if available.
 */
std::optional<SourceLocation> source_at(const SourceMap& map, std::uint64_t address);

/**
 * @brief Attach source information to decoded instructions.
 */
std::vector<SourceInstruction> interleave(
    const SourceMap& map,
    const std::vector<disasm::Instruction>& instructions);

} // namespace roe::debug
