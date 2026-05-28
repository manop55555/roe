// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "roe/disasm.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <initializer_list>
#include <vector>

using namespace roe::disasm;

namespace {

std::vector<std::uint8_t> bytes_of(std::initializer_list<int> values)
{
    std::vector<std::uint8_t> bytes;
    for (const int value : values) {
        bytes.push_back(static_cast<std::uint8_t>(value));
    }
    return bytes;
}

roe::Result<std::vector<Instruction>> decode(const std::vector<std::uint8_t>& bytes, Architecture architecture)
{
    Options options;
    options.architecture = architecture;
    CodeBuffer buffer{0x1000, bytes.begin(), bytes.end()};
    return disassemble_bytes(buffer, options);
}

} // namespace

TEST_CASE("x86-64 decodes and classifies a return", "[disasm][x86]")
{
    const auto bytes = bytes_of({0x55, 0x48, 0x89, 0xe5, 0xc3}); // push rbp; mov rbp,rsp; ret
    const auto result = decode(bytes, Architecture::X86_64);
    REQUIRE(result.has_value());
    REQUIRE(result.value().size() == 3);
    CHECK(result.value().front().mnemonic == "push");
    CHECK(result.value().back().branch_kind == BranchKind::Return);
}

TEST_CASE("x86-64 classifies a direct call with a target", "[disasm][x86]")
{
    const auto bytes = bytes_of({0xe8, 0x00, 0x00, 0x00, 0x00}); // call rel32 -> next insn
    const auto result = decode(bytes, Architecture::X86_64);
    REQUIRE(result.has_value());
    REQUIRE(result.value().size() == 1);
    CHECK(result.value().front().branch_kind == BranchKind::Call);
    REQUIRE(result.value().front().branch_target.has_value());
    CHECK(result.value().front().branch_target.value() == 0x1005);
}

TEST_CASE("aarch64 decodes and classifies a return", "[disasm][aarch64]")
{
    const auto bytes = bytes_of({0xc0, 0x03, 0x5f, 0xd6}); // ret
    const auto result = decode(bytes, Architecture::AArch64);
    REQUIRE(result.has_value());
    REQUIRE(result.value().size() == 1);
    CHECK(result.value().front().mnemonic == "ret");
    CHECK(result.value().front().branch_kind == BranchKind::Return);
}

TEST_CASE("riscv64 decodes a compressed return", "[disasm][riscv]")
{
    const auto bytes = bytes_of({0x82, 0x80}); // c.jr ra  (compressed) -- the return idiom
    const auto result = decode(bytes, Architecture::RiscV64);
    REQUIRE(result.has_value());
    REQUIRE_FALSE(result.value().empty());
    // Capstone classifies jr ra as an indirect jump; either way it must terminate the block.
    CHECK(is_terminal(result.value().front().branch_kind));
}

TEST_CASE("arm, mips, and ppc decode their control-transfer idioms", "[disasm]")
{
    const auto arm = decode(bytes_of({0x1e, 0xff, 0x2f, 0xe1}), Architecture::Arm); // bx lr
    REQUIRE(arm.has_value());
    REQUIRE_FALSE(arm.value().empty());
    CHECK(arm.value().front().mnemonic == "bx");

    const auto mips = decode(bytes_of({0x03, 0xe0, 0x00, 0x08}), Architecture::Mips32); // jr ra (big-endian)
    REQUIRE(mips.has_value());
    REQUIRE_FALSE(mips.value().empty());
    CHECK(mips.value().front().mnemonic == "jr");

    const auto ppc = decode(bytes_of({0x4e, 0x80, 0x00, 0x20}), Architecture::PowerPc32); // blr (big-endian)
    REQUIRE(ppc.has_value());
    REQUIRE_FALSE(ppc.value().empty());
    CHECK(ppc.value().front().mnemonic == "blr");
}

TEST_CASE("x86 RIP-relative load resolves a data reference", "[disasm]")
{
    const auto result = decode(bytes_of({0x48, 0x8d, 0x05, 0x10, 0x00, 0x00, 0x00}), // lea rax, [rip + 0x10]
        Architecture::X86_64);
    REQUIRE(result.has_value());
    REQUIRE_FALSE(result.value().empty());
    REQUIRE(result.value().front().reference_target.has_value());
    CHECK(result.value().front().reference_target.value() == 0x1000U + 7U + 0x10U);
}

TEST_CASE("options_for maps every normalized architecture", "[disasm]")
{
    using BA = roe::binary::Architecture;
    const std::pair<BA, Architecture> table[] = {
        {BA::X86, Architecture::X86},
        {BA::X86_64, Architecture::X86_64},
        {BA::Arm, Architecture::Arm},
        {BA::ArmThumb, Architecture::ArmThumb},
        {BA::AArch64, Architecture::AArch64},
        {BA::RiscV32, Architecture::RiscV32},
        {BA::RiscV64, Architecture::RiscV64},
        {BA::Mips32, Architecture::Mips32},
        {BA::Mips32el, Architecture::Mips32el},
        {BA::Mips64, Architecture::Mips64},
        {BA::Mips64el, Architecture::Mips64el},
        {BA::PowerPc32, Architecture::PowerPc32},
        {BA::PowerPc64, Architecture::PowerPc64},
        {BA::PowerPc64le, Architecture::PowerPc64le},
    };
    for (const auto& entry : table) {
        const auto options = options_for(entry.first);
        REQUIRE(options.has_value());
        CHECK(options.value().architecture == entry.second);
    }
    CHECK_FALSE(options_for(BA::Unknown).has_value());
}

TEST_CASE("every architecture mode opens and decodes", "[disasm]")
{
    struct Case {
        Architecture arch;
        std::vector<std::uint8_t> bytes;
    };
    const std::vector<Case> cases = {
        {Architecture::X86, bytes_of({0xc3})},                        // ret
        {Architecture::ArmThumb, bytes_of({0x70, 0x47})},             // bx lr
        {Architecture::RiscV32, bytes_of({0x82, 0x80})},              // c.jr ra
        {Architecture::Mips32el, bytes_of({0x08, 0x00, 0xe0, 0x03})}, // jr ra (LE)
        {Architecture::Mips64, bytes_of({0x03, 0xe0, 0x00, 0x08})},   // jr ra (BE)
        {Architecture::Mips64el, bytes_of({0x08, 0x00, 0xe0, 0x03})}, // jr ra (LE)
        {Architecture::PowerPc64, bytes_of({0x4e, 0x80, 0x00, 0x20})},   // blr (BE)
        {Architecture::PowerPc64le, bytes_of({0x20, 0x00, 0x80, 0x4e})}, // blr (LE)
    };
    for (const Case& test : cases) {
        const auto result = decode(test.bytes, test.arch);
        REQUIRE(result.has_value());
        CHECK_FALSE(result.value().empty());
    }
}

TEST_CASE("branch predicates are consistent", "[disasm]")
{
    CHECK(is_branch(BranchKind::Call));
    CHECK(is_branch(BranchKind::Return));
    CHECK_FALSE(is_branch(BranchKind::None));
    CHECK(is_terminal(BranchKind::Return));
    CHECK(is_terminal(BranchKind::UnconditionalJump));
    CHECK_FALSE(is_terminal(BranchKind::Call));
    CHECK_FALSE(is_terminal(BranchKind::ConditionalJump));
}
