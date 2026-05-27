// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The roe Authors

#include "roe/binary.hpp"
#include "roe/disasm.hpp"
#include "roe/features.hpp"
#include "roe/format.hpp"
#include "roe/resolver.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace roe::format;
namespace {
bool has(const std::string& haystack, const std::string& needle)
{
    return haystack.find(needle) != std::string::npos;
}
} // namespace

TEST_CASE("banner, version, and help render the expected sections", "[format]")
{
    CHECK(has(render_banner().value(), "disassembler fit for humans"));
    CHECK(has(render_version().value(), "architectures:"));
    CHECK(has(render_version().value(), "capstone:"));
    const std::string help = render_help().value();
    CHECK(has(help, "Input:"));
    CHECK(has(help, "Filtering:"));
    CHECK(has(help, "Examples:"));
    CHECK(has(help, "man roe"));
}

TEST_CASE("help topics cover every documented topic", "[format]")
{
    for (const std::string topic : {"usage", "formats", "arches", "examples", "config", "json"}) {
        const auto rendered = render_help_topic(topic);
        REQUIRE(rendered.has_value());
        CHECK_FALSE(rendered.value().empty());
    }
    CHECK_FALSE(render_help_topic("nonsense").has_value());
}

TEST_CASE("completions render for every supported shell", "[format]")
{
    for (const std::string shell : {"bash", "zsh", "fish", "powershell"}) {
        const auto rendered = render_completions(shell);
        REQUIRE(rendered.has_value());
        CHECK(has(rendered.value(), "roe"));
    }
    CHECK_FALSE(render_completions("tcsh").has_value());
}

TEST_CASE("error rendering includes the message", "[format]")
{
    Options options = default_options();
    options.color = false;
    const auto rendered = render_error(roe::Error{roe::ErrorCode::FileIo, "boom", 0, false}, options);
    CHECK(has(rendered.value(), "boom"));
}

TEST_CASE("xrefs and stats render as text and JSON", "[format]")
{
    Options text = default_options();
    text.color = false;
    Options json = text;
    json.mode = Mode::Json;

    std::vector<roe::features::Xref> xrefs(1);
    xrefs[0].from_function = "main";
    xrefs[0].instruction_address = 0x10;
    xrefs[0].target_name = "printf";
    xrefs[0].instruction_text = "call printf@plt";
    CHECK(has(render_xrefs(xrefs, text).value(), "printf"));
    CHECK(has(render_xrefs(xrefs, json).value(), "\"target\""));
    CHECK(has(render_xrefs({}, text).value(), "no references"));

    std::vector<roe::features::FunctionStats> stats(1);
    stats[0].name = "compute";
    stats[0].size = 42;
    stats[0].basic_blocks = 3;
    stats[0].branch_count = 2;
    stats[0].max_nesting_depth = 1;
    CHECK(has(render_stats(stats, text).value(), "compute"));
    CHECK(has(render_stats(stats, json).value(), "\"basic_blocks\""));
}

TEST_CASE("disassembly, JSON, listing, and sections render from the fixture", "[format]")
{
    const auto loaded = roe::binary::load_file(ROE_FIXTURE_ELF);
    REQUIRE(loaded.has_value());
    const roe::binary::Object& object = loaded.value()->view().objects.front();
    const auto index = roe::resolver::build_index(*loaded.value());
    REQUIRE(index.has_value());

    Options text = default_options();
    text.color = false;
    Options json = text;
    json.mode = Mode::Json;
    Options colored = default_options();
    colored.color = true;

    CHECK(has(render_function_list(loaded.value()->view(), index.value(), text).value(), "compute"));
    CHECK(has(render_sections(loaded.value()->view(), text).value(), ".text"));
    CHECK(has(render_sections(loaded.value()->view(), json).value(), "\"sections\""));

    const auto compute = roe::binary::find_symbol(loaded.value()->view(), 0, "compute");
    REQUIRE(compute.has_value());
    const auto decoded = roe::disasm::disassemble_function(
        *loaded.value(), object, *compute, roe::disasm::options_for(object.architecture).value());
    REQUIRE(decoded.has_value());
    const auto annotated = roe::resolver::annotate(index.value(), decoded.value());

    CHECK_FALSE(render_disassembly(annotated, text).value().empty());
    CHECK_FALSE(render_disassembly(annotated, colored).value().empty());
    CHECK(has(render_json(annotated, text).value(), "\"instructions\""));

    Options with_bytes = text;
    with_bytes.show_bytes = true;
    CHECK_FALSE(render_disassembly(annotated, with_bytes).value().empty());
}
