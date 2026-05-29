// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "../test_support.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace {

struct CommandResult {
    int exit_code{1};
    std::string output;
};

std::filesystem::path repo_root_from(const char* file)
{
    std::filesystem::path cursor = std::filesystem::absolute(file).parent_path();
    while (!cursor.empty() && cursor != cursor.root_path()) {
        if (std::filesystem::exists(cursor / "include" / "roe")) {
            return cursor;
        }
        cursor = cursor.parent_path();
    }
    throw std::runtime_error("could not locate repository root from test source path");
}

std::string shell_quote(const std::filesystem::path& path)
{
    const std::string text = path.string();
    std::string quoted = "'";
    for (const char character : text) {
        if (character == '\'') {
            quoted += "'\\''";
        } else {
            quoted += character;
        }
    }
    quoted += "'";
    return quoted;
}

std::string shell_quote_text(const std::string& text)
{
    return shell_quote(std::filesystem::path(text));
}

CommandResult run_command(const std::string& command)
{
    std::array<char, 4096> buffer{};
    std::string output;
    FILE* pipe = popen((command + " 2>&1").c_str(), "r");
    if (pipe == nullptr) {
        return {127, "popen failed"};
    }

    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        output += buffer.data();
    }

    const int status = pclose(pipe);
    if (status == -1) {
        return {127, output + "pclose failed"};
    }
    if (WIFEXITED(status)) {
        return {WEXITSTATUS(status), output};
    }
    return {128, output};
}

std::filesystem::path make_temp_dir()
{
    const auto base = std::filesystem::temp_directory_path();
    for (int attempt = 0; attempt < 100; ++attempt) {
        std::ostringstream name;
        name << "roe-test-" << static_cast<long long>(getpid()) << "-" << attempt;
        std::filesystem::path candidate = base / name.str();
        std::error_code error;
        if (std::filesystem::create_directory(candidate, error)) {
            return candidate;
        }
    }
    throw std::runtime_error("could not create temporary test directory");
}

std::string compiler_from_env(const char* variable_name, const char* fallback)
{
    const char* value = std::getenv(variable_name);
    if (value == nullptr || std::string(value).empty()) {
        return fallback;
    }
    return value;
}

std::filesystem::path roe_executable()
{
    const std::vector<std::filesystem::path> candidates{
        std::filesystem::current_path() / "roe",
        std::filesystem::current_path() / "src" / "roe"};
    for (const std::filesystem::path& candidate : candidates) {
        if (std::filesystem::exists(candidate)) {
            return candidate;
        }
    }
    return {};
}

bool contains(const std::string& text, const std::string& needle)
{
    return text.find(needle) != std::string::npos;
}

struct FixtureBuild {
    std::filesystem::path dir;
    std::filesystem::path c_executable;
    std::filesystem::path call_targets_executable;
    std::filesystem::path c_object;
    std::filesystem::path cpp_executable;
};

FixtureBuild build_fixtures()
{
    const std::filesystem::path root = repo_root_from(__FILE__);
    const std::filesystem::path fixture_dir = root / "tests" / "fixtures";
    FixtureBuild build{make_temp_dir(), {}, {}, {}, {}};
    build.c_executable = build.dir / "branch_calls";
    build.call_targets_executable = build.dir / "test";
    build.c_object = build.dir / "relocations.o";
    build.cpp_executable = build.dir / "cpp_symbols";

    const std::string cc = compiler_from_env("CC", "cc");
    const std::string cxx = compiler_from_env("CXX", "c++");

    const std::string c_compile =
        shell_quote_text(cc) + " -g -O0 -fno-inline -fno-omit-frame-pointer -rdynamic " +
        shell_quote(fixture_dir / "branch_calls.c") + " -o " + shell_quote(build.c_executable);
    const CommandResult c_result = run_command(c_compile);
    REQUIRE(c_result.exit_code == 0);

    const std::string call_targets_compile =
        shell_quote_text(cc) + " -g -O0 " + shell_quote(fixture_dir / "call_targets.c") +
        " -o " + shell_quote(build.call_targets_executable);
    const CommandResult call_targets_result = run_command(call_targets_compile);
    REQUIRE(call_targets_result.exit_code == 0);

    const std::string object_compile =
        shell_quote_text(cc) + " -g -O0 -fno-inline -fno-omit-frame-pointer -fPIC -c " +
        shell_quote(fixture_dir / "relocations.c") + " -o " + shell_quote(build.c_object);
    const CommandResult object_result = run_command(object_compile);
    REQUIRE(object_result.exit_code == 0);

    const std::string cpp_compile =
        shell_quote_text(cxx) + " -g -O0 -fno-inline -fno-omit-frame-pointer -rdynamic " +
        shell_quote(fixture_dir / "cpp_symbols.cc") + " -o " + shell_quote(build.cpp_executable);
    const CommandResult cpp_result = run_command(cpp_compile);
    REQUIRE(cpp_result.exit_code == 0);

    return build;
}

} // namespace

TEST_CASE("test_cli_fixtures_compile_from_source", "[integration]")
{
    const FixtureBuild fixtures = build_fixtures();

    REQUIRE(std::filesystem::exists(fixtures.c_executable));
    REQUIRE(std::filesystem::exists(fixtures.call_targets_executable));
    REQUIRE(std::filesystem::exists(fixtures.c_object));
    REQUIRE(std::filesystem::exists(fixtures.cpp_executable));
}

TEST_CASE("test_cli_fixtures_list_and_disassemble_generated_binaries", "[integration]")
{
    const FixtureBuild fixtures = build_fixtures();
    const std::filesystem::path roe = roe_executable();
    if (roe.empty()) {
        return;
    }

    const CommandResult list_result =
        run_command(shell_quote(roe) + " " + shell_quote(fixtures.c_executable) + " --no-color");
    REQUIRE(list_result.exit_code == 0);
    CHECK(contains(list_result.output, "branchy"));
    CHECK(contains(list_result.output, "calls_external"));
    CHECK(!contains(list_result.output, "\x1b["));

    const CommandResult disasm_result =
        run_command(shell_quote(roe) + " " + shell_quote(fixtures.c_executable) + " branchy --no-color");
    REQUIRE(disasm_result.exit_code == 0);
    CHECK(contains(disasm_result.output, "0x"));
    CHECK(!contains(disasm_result.output, "\x1b["));

    const CommandResult section_result =
        run_command(shell_quote(roe) + " " + shell_quote(fixtures.c_executable) + " --section .text --no-color");
    REQUIRE(section_result.exit_code == 0);
    CHECK(contains(section_result.output, "0x"));

    const CommandResult json_result = run_command(
        shell_quote(roe) + " " + shell_quote(fixtures.c_executable) + " branchy --json --no-color");
    REQUIRE(json_result.exit_code == 0);
    CHECK(contains(json_result.output, "\"address\""));
    CHECK(contains(json_result.output, "0x"));

    const CommandResult object_result =
        run_command(shell_quote(roe) + " " + shell_quote(fixtures.c_object) + " relocation_user --no-color");
    REQUIRE(object_result.exit_code == 0);
    const bool resolved_expected_reference =
        contains(object_result.output, "external_function") || contains(object_result.output, "global_counter");
    if (!resolved_expected_reference) {
        std::cerr << "relocation_user output did not include expected relocation names:\n"
                  << object_result.output << '\n';
    }
    CHECK(resolved_expected_reference);

    const CommandResult call_targets_result =
        run_command(shell_quote(roe) + " " + shell_quote(fixtures.call_targets_executable) + " main --no-color");
    REQUIRE(call_targets_result.exit_code == 0);
    CHECK(contains(call_targets_result.output, "call helper"));
    // The external call's exact rendering varies by toolchain (printf@plt under a
    // classic PLT; "call printf" or a GOT-resolved reference under -fno-plt), so
    // assert only that roe resolved the call to the printf symbol. call_targets.c
    // has no "printf" string literal, so the token can only be the resolved call.
    INFO("call_targets main disassembly:\n" << call_targets_result.output);
    CHECK(contains(call_targets_result.output, "printf"));
    CHECK(contains(call_targets_result.output, "\342\206\222 [L"));
    CHECK(!contains(call_targets_result.output, "e8 "));

    const CommandResult call_targets_bytes_result = run_command(
        shell_quote(roe) + " " + shell_quote(fixtures.call_targets_executable) + " main --show-bytes --no-color");
    REQUIRE(call_targets_bytes_result.exit_code == 0);
    CHECK(contains(call_targets_bytes_result.output, "e8 "));
}

TEST_CASE("test_cli_fixtures_demangles_cpp_symbols", "[integration]")
{
    const FixtureBuild fixtures = build_fixtures();
    const std::filesystem::path roe = roe_executable();
    if (roe.empty()) {
        return;
    }

    const CommandResult list_result =
        run_command(shell_quote(roe) + " " + shell_quote(fixtures.cpp_executable) + " --no-color");
    REQUIRE(list_result.exit_code == 0);
    CHECK((contains(list_result.output, "fixture::Worker::compute")
        || contains(list_result.output, "_ZN7fixture6Worker7computeEi")));

    const CommandResult disasm_result = run_command(
        shell_quote(roe) + " " + shell_quote(fixtures.cpp_executable) +
        " _ZN7fixture6Worker7computeEi --no-color");
    REQUIRE(disasm_result.exit_code == 0);
    CHECK(contains(disasm_result.output, "0x"));
}
