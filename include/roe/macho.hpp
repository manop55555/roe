// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
#pragma once

/**
 * @file macho.hpp
 * @brief Public Mach-O and universal binary parser entry points.
 */

#include "roe/binary.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace roe::macho {

/**
 * @brief Parsed Mach-O file or fat/universal container.
 */
struct File {
    binary::FileView view;
    std::vector<std::vector<std::uint8_t>> object_images;
};

/**
 * @brief Parse a Mach-O or fat Mach-O file from disk.
 */
Result<File> parse_file(const std::filesystem::path& path);

/**
 * @brief Parse a Mach-O or fat Mach-O file from owned bytes.
 */
Result<File> parse_bytes(std::string source_name, std::vector<std::uint8_t> bytes);

/**
 * @brief Create the format-neutral BinaryFile adapter for a parsed Mach-O file.
 */
Result<std::unique_ptr<binary::BinaryFile>> open_file(const std::filesystem::path& path);

/**
 * @brief Create the format-neutral BinaryFile adapter from owned Mach-O bytes.
 */
Result<std::unique_ptr<binary::BinaryFile>> open_bytes(std::string source_name, std::vector<std::uint8_t> bytes);

} // namespace roe::macho
