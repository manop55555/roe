// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The roe Authors

#include "roe/binary.hpp"
#include "roe/cli.hpp"

#include <catch2/catch_test_macros.hpp>

#include <sstream>
#include <string>
#include <vector>

namespace {

int run_cli(std::vector<std::string> args)
{
    std::vector<char*> argv;
    argv.reserve(args.size());
    for (std::string& arg : args) {
        argv.push_back(arg.data());
    }
    std::ostringstream out;
    std::ostringstream err;
    return roe::cli::main_entry(static_cast<int>(argv.size()), argv.data(), out, err);
}

std::string hex(std::uint64_t value)
{
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}

} // namespace

TEST_CASE("header and table views exit cleanly on the ELF fixture", "[cli][actions]")
{
    using roe::cli::exit_ok;
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--headers"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--sections"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--segments"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--imports"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--exports"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--strings"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--strings", "--min-len", "6"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--find", "main"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--quiet"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "main", "--verbose"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "main", "-v", "-v"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--hex", ".text"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--headers", "--json"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--imports", "--json"}) == exit_ok);
}

TEST_CASE("address-based disassembly exits cleanly on a real function", "[cli][actions]")
{
    const auto loaded = roe::binary::load_file(ROE_FIXTURE_ELF);
    REQUIRE(loaded.has_value());
    const auto functions = roe::binary::function_symbols(loaded.value()->view(), 0);
    REQUIRE_FALSE(functions.empty());
    const std::uint64_t addr = functions.front().address;

    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--addr", hex(addr)}) == roe::cli::exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--range", hex(addr) + "-" + hex(addr + 0x10)}) == roe::cli::exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--hex", "--addr", hex(addr), "--bytes", "32"}) == roe::cli::exit_ok);
}

TEST_CASE("diff exits cleanly for summary and per-function", "[cli][actions]")
{
    CHECK(run_cli({"roe", ROE_FIXTURE_V2, "--diff", ROE_FIXTURE_V1}) == roe::cli::exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_V2, "--diff", ROE_FIXTURE_V1, "--json"}) == roe::cli::exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_V2, "changed_fn", "--diff", ROE_FIXTURE_V1}) == roe::cli::exit_ok);
}

TEST_CASE("CLI argument errors are reported", "[cli][actions]")
{
    using roe::cli::exit_usage;
    CHECK(run_cli({"roe", "--raw-bytes"}) == exit_usage);            // missing --arch
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--addr", "zzz"}) == exit_usage);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--range", "0x10"}) == exit_usage);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--addr", "0x10", "--range", "0x1-0x2"}) == exit_usage);
}

TEST_CASE("CLI JSON variants render across views", "[cli][actions]")
{
    using roe::cli::exit_ok;
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--strings", "--json"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--find", "main", "--json"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--segments", "--json"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--sections", "--json"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--exports", "--json"}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--all"}) == exit_ok);
    // Per-function diff where the function exists in only one binary exercises the one-sided path.
    CHECK(run_cli({"roe", ROE_FIXTURE_V2, "added_fn", "--diff", ROE_FIXTURE_V1}) == exit_ok);
    CHECK(run_cli({"roe", ROE_FIXTURE_V1, "removed_fn", "--diff", ROE_FIXTURE_V2}) == exit_ok);
}

TEST_CASE("CLI view error paths are reported", "[cli][actions]")
{
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--hex", ".nonexistent"}) == roe::cli::exit_file_error);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--addr", "0xfffffff0"}) == roe::cli::exit_file_error);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--diff", "/nonexistent/old.bin"}) == roe::cli::exit_file_error);
    CHECK(run_cli({"roe", ROE_FIXTURE_ELF, "--hex"}) == roe::cli::exit_usage);
}

TEST_CASE("Mach-O and PE views exit cleanly when fixtures exist", "[cli][actions]")
{
    if (std::string(ROE_FIXTURE_MACHO).empty() == false) {
        CHECK(run_cli({"roe", ROE_FIXTURE_MACHO, "--imports"}) == roe::cli::exit_ok);
        CHECK(run_cli({"roe", ROE_FIXTURE_MACHO, "--exports"}) == roe::cli::exit_ok);
        CHECK(run_cli({"roe", ROE_FIXTURE_MACHO, "--headers"}) == roe::cli::exit_ok);
    }
    if (std::string(ROE_FIXTURE_PE).empty() == false) {
        CHECK(run_cli({"roe", ROE_FIXTURE_PE, "--imports"}) == roe::cli::exit_ok);
        CHECK(run_cli({"roe", ROE_FIXTURE_PE, "--sections"}) == roe::cli::exit_ok);
    }
}
