// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
#pragma once

/**
 * @file pe.hpp
 * @brief Public PE/COFF parser entry points.
 */

#include "roe/binary.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace roe::pe {

/**
 * @brief Parsed PE executable, DLL, or COFF object.
 */
struct File {
    binary::FileView view;
    std::vector<std::uint8_t> image;
    std::string pdb_path;
};

/**
 * @brief Parse a PE/COFF file from disk.
 */
Result<File> parse_file(const std::filesystem::path& path);

/**
 * @brief Parse a PE/COFF file from owned bytes.
 */
Result<File> parse_bytes(std::string source_name, std::vector<std::uint8_t> bytes);

/**
 * @brief Create the format-neutral BinaryFile adapter for a parsed PE/COFF file.
 */
Result<std::unique_ptr<binary::BinaryFile>> open_file(const std::filesystem::path& path);

/**
 * @brief Create the format-neutral BinaryFile adapter from owned PE/COFF bytes.
 */
Result<std::unique_ptr<binary::BinaryFile>> open_bytes(std::string source_name, std::vector<std::uint8_t> bytes);

} // namespace roe::pe
