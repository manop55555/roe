// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The roe Authors

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

TEST_CASE("options_for maps normalized architectures", "[disasm]")
{
    CHECK(options_for(roe::binary::Architecture::AArch64).value().architecture == Architecture::AArch64);
    CHECK(options_for(roe::binary::Architecture::Mips64el).value().architecture == Architecture::Mips64el);
    CHECK_FALSE(options_for(roe::binary::Architecture::Unknown).has_value());
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
