#pragma once

/**
 * @file archive.hpp
 * @brief Public static archive parser entry points.
 */

#include "roe/binary.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace roe::archive {

/**
 * @brief One archive member with owned object bytes.
 */
struct Member {
    std::string name;
    std::uint64_t offset{0};
    std::vector<std::uint8_t> bytes;
};

/**
 * @brief Parsed Unix archive, COFF archive, or library collection.
 */
struct File {
    binary::FileView view;
    std::vector<Member> members;
};

/**
 * @brief Parse a static archive from disk.
 */
Result<File> parse_file(const std::filesystem::path& path);

/**
 * @brief Parse a static archive from owned bytes.
 */
Result<File> parse_bytes(std::string source_name, std::vector<std::uint8_t> bytes);

/**
 * @brief Create the format-neutral BinaryFile adapter for a parsed archive.
 */
Result<std::unique_ptr<binary::BinaryFile>> open_file(const std::filesystem::path& path);

/**
 * @brief Create the format-neutral BinaryFile adapter from owned archive bytes.
 */
Result<std::unique_ptr<binary::BinaryFile>> open_bytes(std::string source_name, std::vector<std::uint8_t> bytes);

} // namespace roe::archive
