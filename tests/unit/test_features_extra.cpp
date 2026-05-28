// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "roe/binary.hpp"
#include "roe/disasm.hpp"
#include "roe/features.hpp"
#include "roe/resolver.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <string>
#include <vector>

namespace {

struct Loaded {
    std::unique_ptr<roe::binary::BinaryFile> file;
    roe::resolver::Index index;
    std::vector<roe::features::FunctionBody> bodies;
};

Loaded load(const char* path)
{
    Loaded result;
    auto loaded = roe::binary::load_file(path);
    REQUIRE(loaded.has_value());
    result.file = std::move(loaded).value();
    const roe::binary::Object& object = result.file->view().objects.front();
    auto index = roe::resolver::build_index(*result.file);
    REQUIRE(index.has_value());
    result.index = std::move(index).value();
    const roe::disasm::Options decode = roe::disasm::options_for(object.architecture).value();
    for (const roe::binary::Symbol& symbol : object.symbols) {
        if (symbol.type != roe::binary::SymbolType::Function || !symbol.defined || symbol.name.empty()) {
            continue;
        }
        const auto decoded = roe::disasm::disassemble_function(*result.file, object, symbol, decode);
        if (!decoded) {
            continue;
        }
        auto annotated = roe::resolver::annotate(result.index, decoded.value());
        annotated = roe::features::annotate_string_references(object, annotated);
        result.bodies.push_back(roe::features::FunctionBody{symbol, std::move(annotated)});
    }
    return result;
}

} // namespace

TEST_CASE("find_string_references links a string to its referencing function", "[features]")
{
    const Loaded loaded = load(ROE_FIXTURE_ELF);
    const roe::binary::Object& object = loaded.file->view().objects.front();
    const std::vector<roe::features::StringRef> refs =
        roe::features::find_string_references(object.strings, loaded.bodies, 4U);

    bool found_referenced = false;
    for (const roe::features::StringRef& ref : refs) {
        if (ref.value.find("roe sample result") != std::string::npos) {
            CHECK(ref.referenced);
            CHECK(ref.from_function == "main");
            found_referenced = true;
        }
    }
    CHECK(found_referenced);
}

TEST_CASE("find_string_references honors min length", "[features]")
{
    std::vector<roe::binary::StringLiteral> strings;
    strings.push_back({0, 0x10, 3, "abc"});
    strings.push_back({0, 0x20, 8, "longone!"});
    const std::vector<roe::features::FunctionBody> none;
    const auto refs = roe::features::find_string_references(strings, none, 5U);
    REQUIRE(refs.size() == 1);
    CHECK(refs.front().value == "longone!");
    CHECK_FALSE(refs.front().referenced);
}

TEST_CASE("diff_functions classifies added, removed, and changed", "[features]")
{
    const Loaded older = load(ROE_FIXTURE_V1);
    const Loaded newer = load(ROE_FIXTURE_V2);
    const roe::features::DiffResult result = roe::features::diff_functions(older.bodies, newer.bodies);

    const auto contains = [](const std::vector<std::string>& v, const std::string& n) {
        return std::find(v.begin(), v.end(), n) != v.end();
    };
    CHECK(contains(result.added, "added_fn"));
    CHECK(contains(result.removed, "removed_fn"));
    CHECK(contains(result.changed, "changed_fn"));
    CHECK(result.unchanged >= 1);
}
