#pragma once

/**
 * @file disasm.hpp
 * @brief Public disassembly model and Capstone-backed entry points.
 */

#include "roe/core.hpp"
#include "roe/binary.hpp"
#include "roe/elf.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace roe::disasm {

enum class Architecture : std::uint8_t {
    X86,
    X86_64,
    Arm,
    ArmThumb,
    AArch64,
    RiscV32,
    RiscV64,
    Mips32,
    Mips32el,
    Mips64,
    Mips64el,
    PowerPc32,
    PowerPc64,
    PowerPc64le
};
enum class Syntax : std::uint8_t { Intel, Att };

enum class BranchKind : std::uint8_t {
    None,
    UnconditionalJump,
    ConditionalJump,
    Call,
    Return,
    IndirectJump,
    IndirectCall
};

/**
 * @brief Borrowed code buffer for disassembly.
 */
struct CodeBuffer {
    std::uint64_t address{0};
    std::vector<std::uint8_t>::const_iterator begin;
    std::vector<std::uint8_t>::const_iterator end;
};

/**
 * @brief Disassembler options.
 */
struct Options {
    Architecture architecture{Architecture::X86_64};
    Syntax syntax{Syntax::Intel};
    bool resolve_branch_targets{true};
};

/**
 * @brief Decoded instruction with preserved address and byte encoding.
 */
struct Instruction {
    std::uint64_t address{0};
    std::uint8_t size{0};
    std::vector<std::uint8_t> bytes;
    std::string mnemonic;
    std::string operands;
    BranchKind branch_kind{BranchKind::None};
    std::optional<std::uint64_t> branch_target;
};

/**
 * @brief Disassemble an arbitrary code buffer.
 */
Result<std::vector<Instruction>> disassemble_bytes(CodeBuffer code, const Options& options);

/**
 * @brief Convert a normalized binary architecture into disassembler options.
 */
Result<Options> options_for(binary::Architecture architecture, Syntax syntax = Syntax::Intel);

/**
 * @brief Disassemble owned section bytes from any supported binary format.
 */
Result<std::vector<Instruction>> disassemble_section(
    const binary::SectionBytes& section,
    const Options& options);

/**
 * @brief Disassemble a normalized function symbol from any supported binary format.
 */
Result<std::vector<Instruction>> disassemble_function(
    const binary::BinaryFile& file,
    const binary::Object& object,
    const binary::Symbol& symbol,
    const Options& options);

/**
 * @brief Disassemble a function symbol from an ELF file.
 */
Result<std::vector<Instruction>> disassemble_function(
    const elf::File& file,
    const elf::Symbol& symbol,
    const Options& options);

/**
 * @brief Disassemble an executable section from an ELF file.
 */
Result<std::vector<Instruction>> disassemble_section(
    const elf::File& file,
    const elf::Section& section,
    const Options& options);

/**
 * @brief Return whether a branch kind changes control flow.
 */
bool is_branch(BranchKind kind) noexcept;

/**
 * @brief Return whether a branch kind terminates the current linear block.
 */
bool is_terminal(BranchKind kind) noexcept;

} // namespace roe::disasm
