// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

// Fuzz the PE/COFF parser directly from untrusted bytes, exercising the import
// and export table walks (RVA translation), the COFF symbol/string-table walk,
// and the BinaryFile adapter.

#include "roe/pe.hpp"

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace {
constexpr std::size_t max_input_size = 4U * 1024U * 1024U;
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

    auto loaded = roe::pe::open_bytes("fuzz-input", std::move(bytes));
    if (!loaded) {
        return 0;
    }
    const roe::binary::FileView& view = loaded.value()->view();
    std::size_t sink = 0;
    for (const roe::binary::Object& object : view.objects) {
        for (const roe::binary::Section& section : object.sections) {
            const auto contents = loaded.value()->section_bytes(section);
            static_cast<void>(contents);
        }
        // Touch every parsed symbol (COFF symbol-table walk + string-table names).
        for (const roe::binary::Symbol& symbol : object.symbols) {
            sink += symbol.name.size() + static_cast<std::size_t>(symbol.address);
        }
    }
    static_cast<void>(sink);
    return 0;
}
