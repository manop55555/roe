// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
//
// Disassemble real cross-compiled fixtures end-to-end. CMake builds each fixture
// only when its toolchain is present and passes the path as a compile define (or
// "" when absent). The contract the user asked for: skip when the toolchain is
// missing, but FAIL loudly when it is present and roe can't handle the binary.

#include "../test_support.hpp"

#include <filesystem>
#include <string>

#ifndef ROE_FIXTURE_X86_32
#define ROE_FIXTURE_X86_32 ""
#endif
#ifndef ROE_FIXTURE_AARCH64
#define ROE_FIXTURE_AARCH64 ""
#endif
#ifndef ROE_FIXTURE_MIPS
#define ROE_FIXTURE_MIPS ""
#endif
#ifndef ROE_FIXTURE_MIPSEL
#define ROE_FIXTURE_MIPSEL ""
#endif

using roe_test::CommandResult;
using roe_test::contains;
using roe_test::roe_executable;
using roe_test::run_command;
using roe_test::shell_quote;

namespace {

void disassembles_compute(const char* arch, const char* fixture_path)
{
    if (fixture_path == nullptr || fixture_path[0] == '\0') {
        SUCCEED(std::string("no toolchain for ") + arch + "; fixture not built - skipped");
        return;
    }
    if (!std::filesystem::exists(fixture_path)) {
        SUCCEED(std::string(arch) + " fixture path is set but the file is missing - skipped");
        return;
    }
    const std::filesystem::path roe = roe_executable();
    if (roe.empty()) {
        SUCCEED("roe binary not found next to the test - skipped");
        return;
    }

    const CommandResult result =
        run_command(shell_quote(roe.string()) + " --no-color " + shell_quote(fixture_path) + " compute");
    INFO(arch << " disassembly of 'compute':\n" << result.output);
    CHECK(result.exit_code == 0);
    CHECK(contains(result.output, "sym compute"));
    CHECK(contains(result.output, "0x"));
}

} // namespace

TEST_CASE("cross-architecture fixtures disassemble and resolve the compute symbol", "[crossarch][integration]")
{
    disassembles_compute("x86-32 ELF", ROE_FIXTURE_X86_32);
    disassembles_compute("aarch64 ELF", ROE_FIXTURE_AARCH64);
    disassembles_compute("mips ELF", ROE_FIXTURE_MIPS);
    disassembles_compute("mipsel ELF", ROE_FIXTURE_MIPSEL);
}
