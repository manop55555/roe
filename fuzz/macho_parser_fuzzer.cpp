// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

// Fuzz the Mach-O parser directly from untrusted bytes, including fat dispatch
// and the BinaryFile adapter's section_bytes. Run with libFuzzer + ASan/UBSan.

#include "roe/macho.hpp"

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

    auto loaded = roe::macho::open_bytes("fuzz-input", std::move(bytes));
    if (!loaded) {
        return 0;
    }
    const roe::binary::FileView& view = loaded.value()->view();
    for (const roe::binary::Object& object : view.objects) {
        for (const roe::binary::Section& section : object.sections) {
            const auto contents = loaded.value()->section_bytes(section);
            static_cast<void>(contents);
        }
    }
    return 0;
}
