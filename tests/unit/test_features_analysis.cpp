// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "roe/binary.hpp"
#include "roe/disasm.hpp"
#include "roe/features.hpp"
#include "roe/resolver.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

namespace {

std::vector<roe::features::FunctionBody> build_bodies(
    const roe::binary::BinaryFile& file,
    const roe::binary::Object& object,
    const roe::resolver::Index& index)
{
    std::vector<roe::features::FunctionBody> bodies;
    const roe::disasm::Options decode = roe::disasm::options_for(object.architecture).value();
    for (const roe::binary::Symbol& symbol : object.symbols) {
        if (symbol.type != roe::binary::SymbolType::Function || !symbol.defined || symbol.name.empty()) {
            continue;
        }
        const auto decoded = roe::disasm::disassemble_function(file, object, symbol, decode);
        if (!decoded) {
            continue;
        }
        auto annotated = roe::resolver::annotate(index, decoded.value());
        annotated = roe::features::annotate_string_references(object, annotated);
        bodies.push_back(roe::features::FunctionBody{symbol, std::move(annotated)});
    }
    return bodies;
}

} // namespace

TEST_CASE("filter_functions applies a regex and rejects bad patterns", "[features]")
{
    std::vector<roe::binary::Symbol> functions(3);
    functions[0].name = "compute";
    functions[0].raw_name = "compute";
    functions[1].name = "main";
    functions[1].raw_name = "main";
    functions[2].name = "square";
    functions[2].raw_name = "square";

    const auto matched = roe::features::filter_functions(functions, "comp|squ");
    REQUIRE(matched.has_value());
    CHECK(matched.value().size() == 2);

    const auto invalid = roe::features::filter_functions(functions, "(unterminated");
    REQUIRE_FALSE(invalid.has_value());
    CHECK(invalid.error().code == roe::ErrorCode::Usage);
}

TEST_CASE("calls, xrefs, stats, and string refs on the fixture", "[features]")
{
    const auto loaded = roe::binary::load_file(ROE_FIXTURE_ELF);
    REQUIRE(loaded.has_value());
    const roe::binary::Object& object = loaded.value()->view().objects.front();
    const auto index = roe::resolver::build_index(*loaded.value());
    REQUIRE(index.has_value());
    const auto bodies = build_bodies(*loaded.value(), object, index.value());
    REQUIRE_FALSE(bodies.empty());

    const auto callers = roe::features::functions_calling(bodies, "compute");
    bool main_calls_compute = false;
    for (const roe::binary::Symbol& caller : callers) {
        if (caller.name == "main") {
            main_calls_compute = true;
        }
    }
    CHECK(main_calls_compute);

    const auto xrefs = roe::features::find_xrefs(bodies, "compute");
    CHECK_FALSE(xrefs.empty());

    const auto stats = roe::features::compute_stats(bodies);
    bool checked_compute = false;
    for (const roe::features::FunctionStats& entry : stats) {
        if (entry.name == "compute") {
            CHECK(entry.basic_blocks >= 2);
            CHECK(entry.branch_count >= 1);
            checked_compute = true;
        }
    }
    CHECK(checked_compute);

    const auto referencing = roe::features::functions_containing_string(bodies, "roe sample result");
    CHECK_FALSE(referencing.empty());
}

TEST_CASE("config falls back to defaults when the file is absent", "[features]")
{
    setenv("ROE_CONFIG", "/nonexistent/path/roe-config.toml", 1);
    const roe::features::Config config = roe::features::load_config();
    CHECK(config.color);
    CHECK(config.pager);
    CHECK_FALSE(config.show_bytes);
    unsetenv("ROE_CONFIG");
}
