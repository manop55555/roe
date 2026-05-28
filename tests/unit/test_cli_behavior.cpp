// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The roe Authors

#include "roe/cli.hpp"

#include <catch2/catch_test_macros.hpp>

#include <iostream>
#include <sstream>
#include <streambuf>
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

struct CliRun {
    int code;
    std::string out;
    std::string err;
};

// Run main_entry capturing stdout and stderr, with stdin_text fed on std::cin
// (so --raw-bytes stdin paths are testable without a subprocess).
CliRun run_capture(std::vector<std::string> args, const std::string& stdin_text = "")
{
    std::vector<char*> argv;
    argv.reserve(args.size());
    for (std::string& arg : args) {
        argv.push_back(arg.data());
    }
    std::ostringstream out;
    std::ostringstream err;
    std::istringstream input(stdin_text);
    std::streambuf* saved = std::cin.rdbuf(input.rdbuf());
    const int code = main_entry(static_cast<int>(argv.size()), argv.data(), out, err);
    std::cin.rdbuf(saved);
    return CliRun{code, out.str(), err.str()};
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

// Anomaly 1: color must be auto-gated to a TTY, with --color overrides.
TEST_CASE("resolve_use_color follows mode precedence", "[cli][color]")
{
    const Arguments automatic;
    CHECK(resolve_use_color(automatic, false, /*tty=*/true, /*config=*/true));
    CHECK_FALSE(resolve_use_color(automatic, false, /*tty=*/false, true)); // piped -> off
    CHECK_FALSE(resolve_use_color(automatic, /*no_color_env=*/true, true, true)); // NO_COLOR
    CHECK_FALSE(resolve_use_color(automatic, false, true, /*config=*/false)); // config off

    Arguments always;
    always.color_always = true;
    CHECK(resolve_use_color(always, /*no_color_env=*/true, /*tty=*/false, /*config=*/false)); // overrides all

    Arguments never;
    never.no_color = true;
    CHECK_FALSE(resolve_use_color(never, false, true, true));

    Arguments quiet;
    quiet.quiet = true;
    quiet.color_always = true;
    CHECK_FALSE(resolve_use_color(quiet, false, true, true)); // quiet wins
}

TEST_CASE("parse_args understands --color modes", "[cli][color]")
{
    CHECK(parse({"roe", "a.out", "main", "--color=always"}).value().color_always);
    CHECK(parse({"roe", "a.out", "main", "--color", "always"}).value().color_always);
    CHECK(parse({"roe", "a.out", "main", "--color=never"}).value().no_color);
    const Arguments automatic = parse({"roe", "a.out", "main", "--color=auto"}).value();
    CHECK_FALSE(automatic.color_always);
    CHECK_FALSE(automatic.no_color);
    CHECK_FALSE(parse({"roe", "a.out", "--color=bogus"}).has_value());
}

TEST_CASE("--color=always emits ANSI; --no-color suppresses it", "[cli][color]")
{
    const CliRun always = run_capture({"roe", ROE_FIXTURE_ELF, "compute", "--color=always"});
    CHECK(always.code == exit_ok);
    CHECK(always.out.find("\033[") != std::string::npos);
    const CliRun off = run_capture({"roe", ROE_FIXTURE_ELF, "compute", "--no-color"});
    CHECK(off.code == exit_ok);
    CHECK(off.out.find("\033[") == std::string::npos);
}

// Anomaly 4: bare `roe` is a usage error printed to stderr; explicit help is success on stdout.
TEST_CASE("no-arguments prints help to stderr and exits 1", "[cli]")
{
    const CliRun bare = run_capture({"roe"});
    CHECK(bare.code == exit_usage);
    CHECK(bare.out.empty());
    CHECK(bare.err.find("Usage") != std::string::npos);

    const CliRun help = run_capture({"roe", "--help"});
    CHECK(help.code == exit_ok);
    CHECK(help.err.empty());
    CHECK(help.out.find("Usage") != std::string::npos);
}

// Anomaly 3: --bytes beyond the section is clamped, with a note on stderr.
TEST_CASE("--hex --bytes past the section end notes the clamp", "[cli][hex]")
{
    const CliRun run = run_capture({"roe", ROE_FIXTURE_ELF, "--hex", ".text", "--bytes", "999999999"});
    CHECK(run.code == exit_ok);
    CHECK(run.err.find("clamp") != std::string::npos);
}

// Anomaly 5: --raw-bytes notes invalid hex (auto) and reports it distinctly under --hex-input.
TEST_CASE("--raw-bytes handles non-hex text honestly", "[cli][rawbytes]")
{
    const CliRun note = run_capture({"roe", "--raw-bytes", "--arch", "x86_64"}, "zz zz\n");
    CHECK(note.code == exit_ok);
    CHECK(note.err.find("not valid hex") != std::string::npos);

    const CliRun forced = run_capture({"roe", "--raw-bytes", "--hex-input", "--arch", "x86_64"}, "zz zz\n");
    CHECK(forced.code == exit_usage);
    CHECK(forced.err.find("no valid hex digits") != std::string::npos);

    const CliRun valid = run_capture({"roe", "--raw-bytes", "--arch", "x86_64"}, "55 c3\n");
    CHECK(valid.code == exit_ok);
    CHECK(valid.out.find("push") != std::string::npos);
    CHECK(valid.err.empty());
}
