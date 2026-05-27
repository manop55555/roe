// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The roe Authors

// Exercises the full roe pipeline from untrusted bytes: format detection, ELF
// parsing and normalization, resolver index construction, and disassembly of the
// first function symbol. Run with libFuzzer + ASan/UBSan.

#include "roe/binary.hpp"
#include "roe/disasm.hpp"
#include "roe/resolver.hpp"

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

    auto loaded = roe::binary::load_bytes("fuzz-input", std::move(bytes));
    if (!loaded) {
        return 0;
    }

    const roe::binary::FileView& view = loaded.value()->view();
    const auto index = roe::resolver::build_index(*loaded.value());
    if (!index || view.objects.empty()) {
        return 0;
    }

    const roe::binary::Object& object = view.objects.front();
    const auto options = roe::disasm::options_for(object.architecture);
    if (!options) {
        return 0;
    }

    std::size_t disassembled = 0;
    for (const roe::binary::Symbol& symbol : object.symbols) {
        if (symbol.type != roe::binary::SymbolType::Function || !symbol.defined) {
            continue;
        }
        const auto decoded = roe::disasm::disassemble_function(*loaded.value(), object, symbol, options.value());
        if (decoded) {
            const auto annotated = roe::resolver::annotate(index.value(), decoded.value());
            static_cast<void>(annotated);
        }
        if (++disassembled >= 8U) {
            break;
        }
    }
    return 0;
}
