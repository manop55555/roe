// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The roe Authors

#include "roe/cli.hpp"

#include <catch2/catch_test_macros.hpp>

#include <sstream>
#include <string>
#include <vector>

using namespace roe::cli;

namespace {

roe::Result<Arguments> parse(std::vector<std::string> args)
{
    std::vector<char*> argv;
    argv.reserve(args.size());
    for (std::string& arg : args) {
        argv.push_back(arg.data());
    }
    return parse_args(static_cast<int>(argv.size()), argv.data());
}

int run_cli(std::vector<std::string> args)
{
    std::vector<char*> argv;
    argv.reserve(args.size());
    for (std::string& arg : args) {
        argv.push_back(arg.data());
    }
    std::ostringstream out;
    std::ostringstream err;
    return main_entry(static_cast<int>(argv.size()), argv.data(), out, err);
}

} // namespace

TEST_CASE("parse_args selects the right action", "[cli]")
{
    CHECK(parse({"roe"}).value().action == Action::ShowHelp);
    CHECK(parse({"roe", "--version"}).value().action == Action::ShowVersion);
    CHECK(parse({"roe", "-h"}).value().action == Action::ShowHelp);

    const Arguments help_topic = parse({"roe", "--help", "arches"}).value();
    CHECK(help_topic.action == Action::ShowHelp);
    REQUIRE(help_topic.help_topic.has_value());
    CHECK(help_topic.help_topic.value() == "arches");

    CHECK(parse({"roe", "a.out"}).value().action == Action::ListFunctions);
    CHECK(parse({"roe", "a.out", "main"}).value().action == Action::DisassembleSymbol);
    CHECK(parse({"roe", "a.out", "--section", ".text"}).value().action == Action::DisassembleSection);
    CHECK(parse({"roe", "a.out", "--all"}).value().action == Action::DisassembleAll);
    CHECK(parse({"roe", "a.out", "-D"}).value().action == Action::DisassembleAll);
    CHECK(parse({"roe", "a.out", "--xref", "malloc"}).value().action == Action::ShowXrefs);
    CHECK(parse({"roe", "a.out", "--stats"}).value().action == Action::ShowStats);
    CHECK(parse({"roe", "a.out", "--grep", "init"}).value().action == Action::ListFunctions);
    CHECK(parse({"roe", "--completions", "bash"}).value().action == Action::ShowCompletions);
}

TEST_CASE("parse_args captures flags", "[cli]")
{
    const Arguments args = parse({"roe", "a.out", "main", "--json", "--no-color", "--show-bytes", "--source"}).value();
    CHECK(args.json);
    CHECK(args.no_color);
    CHECK(args.show_bytes);
    CHECK(args.source);
    CHECK(args.symbol.value() == "main");
}

TEST_CASE("parse_args rejects invalid input", "[cli]")
{
    CHECK_FALSE(parse({"roe", "--bogus"}).has_value());
    CHECK_FALSE(parse({"roe", "a.out", "main", "--section", ".text"}).has_value());
    CHECK_FALSE(parse({"roe", "--section"}).has_value());
    CHECK_FALSE(parse({"roe", "--arch", "nonsense"}).has_value());
    CHECK_FALSE(parse({"roe", "a", "b", "c"}).has_value());
}

TEST_CASE("main_entry returns documented exit codes", "[cli]")
{
    CHECK(run_cli({"roe", "--help"}) == exit_ok);
    CHECK(run_cli({"roe", "--version"}) == exit_ok);
    CHECK(run_cli({"roe", "--bogus"}) == exit_usage);
    CHECK(run_cli({"roe", "/nonexistent/path/to/binary"}) == exit_file_error);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "compute"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "compute", "--json"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--section", ".text"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--stats"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--xref", "compute"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "nonexistent_symbol"}) == exit_disasm_error);
}

TEST_CASE("main_entry runs every workflow on the fixture", "[cli]")
{
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--all"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--grep", "comp"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--calls", "printf"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--contains", "result"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "compute", "--source"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "compute", "--show-bytes"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "compute", "--no-color"}) == exit_ok);
    CHECK(run_cli({"roe", "--completions", "zsh"}) == exit_ok);
    CHECK(run_cli({"roe", "--help", "json"}) == exit_ok);
    CHECK(run_cli({"roe", "--help", "bogus"}) == exit_usage);
    CHECK(run_cli({"roe", "--completions", "tcsh"}) == exit_usage);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--section", ".does_not_exist"}) == exit_file_error);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "compute", "--arch", "x86_64"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--grep", "zzzznomatch"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--contains", "zzzznomatch"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--calls", "zzzznomatch"}) == exit_ok);
}
