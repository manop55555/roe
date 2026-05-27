// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The roe Authors
#include "roe/elf.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr std::size_t max_input_size = 4U * 1024U * 1024U;
constexpr std::size_t max_accessor_iterations = 256U;

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    if (size > max_input_size) {
        return 0;
    }

    std::vector<std::uint8_t> bytes;
    if (size > 0U) {
        bytes.assign(data, data + size);
    }

    auto parsed = roe::elf::parse_bytes("libFuzzer-input", std::move(bytes));
    if (!parsed) {
        return 0;
    }

    const auto& file = parsed.value();

    const auto functions = roe::elf::function_symbols(file);
    for (const auto& symbol : functions) {
        if (!symbol.name.empty()) {
            (void)roe::elf::find_symbol(file, symbol.name);
        }
    }

    const auto section_limit = std::min(file.sections.size(), max_accessor_iterations);
    for (std::size_t index = 0; index < section_limit; ++index) {
        const auto& section = file.sections[index];
        if (!section.name.empty()) {
            (void)roe::elf::find_section(file, section.name);
        }

        const auto section_data = roe::elf::section_bytes(file, section);
        if (section_data) {
            // Touch the borrowed range lightly so invalid iterators become sanitizer-visible.
            const auto begin = section_data->begin;
            const auto end = section_data->end;
            if (begin != end) {
                volatile std::uint8_t first = *begin;
                (void)first;
            }
        }
    }

    return 0;
}
