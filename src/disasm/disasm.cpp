// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The roe Authors

#include "roe/disasm.hpp"

#include <capstone/capstone.h>
#include <capstone/arm.h>
#include <capstone/arm64.h>
#include <capstone/mips.h>
#include <capstone/ppc.h>
#include <capstone/riscv.h>
#include <capstone/x86.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <iterator>
#include <limits>
#include <optional>
#include <string_view>
#include <utility>

namespace roe::disasm {
namespace {

class CapstoneHandle {
public:
    explicit CapstoneHandle(csh handle) noexcept : handle_(handle) {}

    CapstoneHandle(const CapstoneHandle&) = delete;
    CapstoneHandle& operator=(const CapstoneHandle&) = delete;

    CapstoneHandle(CapstoneHandle&& other) noexcept : handle_(std::exchange(other.handle_, 0)) {}

    CapstoneHandle& operator=(CapstoneHandle&& other) noexcept {
        if (this != &other) {
            close();
            handle_ = std::exchange(other.handle_, 0);
        }
        return *this;
    }

    ~CapstoneHandle() { close(); }

    [[nodiscard]] csh get() const noexcept { return handle_; }

private:
    void close() noexcept {
        if (handle_ != 0) {
            csh handle = handle_;
            static_cast<void>(cs_close(&handle));
            handle_ = 0;
        }
    }

    csh handle_{0};
};

class InstructionBlock {
public:
    InstructionBlock(cs_insn* instructions, std::size_t count) noexcept
        : instructions_(instructions), count_(count) {}

    InstructionBlock(const InstructionBlock&) = delete;
    InstructionBlock& operator=(const InstructionBlock&) = delete;

    InstructionBlock(InstructionBlock&& other) noexcept
        : instructions_(std::exchange(other.instructions_, nullptr)),
          count_(std::exchange(other.count_, 0)) {}

    InstructionBlock& operator=(InstructionBlock&& other) noexcept {
        if (this != &other) {
            release();
            instructions_ = std::exchange(other.instructions_, nullptr);
            count_ = std::exchange(other.count_, 0);
        }
        return *this;
    }

    ~InstructionBlock() { release(); }

    [[nodiscard]] const cs_insn* begin() const noexcept { return instructions_; }
    [[nodiscard]] const cs_insn* end() const noexcept { return instructions_ + count_; }
    [[nodiscard]] std::size_t count() const noexcept { return count_; }

private:
    void release() noexcept {
        if (instructions_ != nullptr) {
            cs_free(instructions_, count_);
            instructions_ = nullptr;
            count_ = 0;
        }
    }

    cs_insn* instructions_{nullptr};
    std::size_t count_{0};
};

enum class Family { X86, Arm, Arm64, Mips, Ppc, RiscV };

Family family_of(Architecture architecture) noexcept {
    switch (architecture) {
    case Architecture::X86:
    case Architecture::X86_64:
        return Family::X86;
    case Architecture::Arm:
    case Architecture::ArmThumb:
        return Family::Arm;
    case Architecture::AArch64:
        return Family::Arm64;
    case Architecture::RiscV32:
    case Architecture::RiscV64:
        return Family::RiscV;
    case Architecture::Mips32:
    case Architecture::Mips32el:
    case Architecture::Mips64:
    case Architecture::Mips64el:
        return Family::Mips;
    case Architecture::PowerPc32:
    case Architecture::PowerPc64:
    case Architecture::PowerPc64le:
        return Family::Ppc;
    }
    return Family::X86;
}

struct EngineConfig {
    cs_arch arch{CS_ARCH_X86};
    cs_mode mode{CS_MODE_64};
};

cs_mode combine_mode(unsigned value) noexcept { return static_cast<cs_mode>(value); }

EngineConfig config_for(Architecture architecture) noexcept {
    switch (architecture) {
    case Architecture::X86:
        return {CS_ARCH_X86, CS_MODE_32};
    case Architecture::X86_64:
        return {CS_ARCH_X86, CS_MODE_64};
    case Architecture::Arm:
        return {CS_ARCH_ARM, CS_MODE_ARM};
    case Architecture::ArmThumb:
        return {CS_ARCH_ARM, CS_MODE_THUMB};
    case Architecture::AArch64:
        return {CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN};
    case Architecture::RiscV32:
        return {CS_ARCH_RISCV, combine_mode(CS_MODE_RISCV32 | CS_MODE_RISCVC)};
    case Architecture::RiscV64:
        return {CS_ARCH_RISCV, combine_mode(CS_MODE_RISCV64 | CS_MODE_RISCVC)};
    case Architecture::Mips32:
        return {CS_ARCH_MIPS, combine_mode(CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN)};
    case Architecture::Mips32el:
        return {CS_ARCH_MIPS, combine_mode(CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)};
    case Architecture::Mips64:
        return {CS_ARCH_MIPS, combine_mode(CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN)};
    case Architecture::Mips64el:
        return {CS_ARCH_MIPS, combine_mode(CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN)};
    case Architecture::PowerPc32:
        return {CS_ARCH_PPC, combine_mode(CS_MODE_32 | CS_MODE_BIG_ENDIAN)};
    case Architecture::PowerPc64:
        return {CS_ARCH_PPC, combine_mode(CS_MODE_64 | CS_MODE_BIG_ENDIAN)};
    case Architecture::PowerPc64le:
        return {CS_ARCH_PPC, combine_mode(CS_MODE_64 | CS_MODE_LITTLE_ENDIAN)};
    }
    return {CS_ARCH_X86, CS_MODE_64};
}

Result<CapstoneHandle> open_engine(const Options& options) {
    const EngineConfig config = config_for(options.architecture);

    csh raw_handle = 0;
    const cs_err open_result = cs_open(config.arch, config.mode, &raw_handle);
    if (open_result != CS_ERR_OK) {
        return Result<CapstoneHandle>::err(
            {ErrorCode::Disassembly, std::string("failed to open Capstone engine: ") + cs_strerror(open_result)});
    }

    CapstoneHandle handle(raw_handle);
    const cs_err detail_result = cs_option(handle.get(), CS_OPT_DETAIL, CS_OPT_ON);
    if (detail_result != CS_ERR_OK) {
        return Result<CapstoneHandle>::err(
            {ErrorCode::Disassembly, std::string("failed to enable Capstone details: ") + cs_strerror(detail_result)});
    }

    if (options.syntax == Syntax::Att && family_of(options.architecture) == Family::X86) {
        const cs_err syntax_result = cs_option(handle.get(), CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
        if (syntax_result != CS_ERR_OK) {
            return Result<CapstoneHandle>::err(
                {ErrorCode::Disassembly, std::string("failed to select AT&T syntax: ") + cs_strerror(syntax_result)});
        }
    }

    return Result<CapstoneHandle>::ok(std::move(handle));
}

[[nodiscard]] bool has_group(const cs_insn& instruction, unsigned int group) noexcept {
    if (instruction.detail == nullptr) {
        return false;
    }
    for (std::uint8_t index = 0; index < instruction.detail->groups_count; ++index) {
        if (instruction.detail->groups[index] == group) {
            return true;
        }
    }
    return false;
}

// Extract the first immediate operand of a branch instruction. Capstone reports
// relative branch targets as absolute addresses across every supported ISA, so a
// branch's first immediate operand is its target.
[[nodiscard]] std::optional<std::uint64_t> direct_target(Architecture architecture, const cs_insn& in) noexcept {
    if (in.detail == nullptr) {
        return std::nullopt;
    }
    const auto as_u64 = [](std::int64_t value) noexcept { return static_cast<std::uint64_t>(value); };

    switch (family_of(architecture)) {
    case Family::X86: {
        const cs_x86& detail = in.detail->x86;
        for (std::uint8_t i = 0; i < detail.op_count; ++i) {
            if (detail.operands[i].type == X86_OP_IMM) {
                return as_u64(detail.operands[i].imm);
            }
        }
        break;
    }
    case Family::Arm: {
        const cs_arm& detail = in.detail->arm;
        for (std::uint8_t i = 0; i < detail.op_count; ++i) {
            if (detail.operands[i].type == ARM_OP_IMM) {
                return as_u64(static_cast<std::int64_t>(detail.operands[i].imm));
            }
        }
        break;
    }
    case Family::Arm64: {
        const cs_arm64& detail = in.detail->arm64;
        for (std::uint8_t i = 0; i < detail.op_count; ++i) {
            if (detail.operands[i].type == ARM64_OP_IMM) {
                return as_u64(detail.operands[i].imm);
            }
        }
        break;
    }
    case Family::Mips: {
        const cs_mips& detail = in.detail->mips;
        for (std::uint8_t i = 0; i < detail.op_count; ++i) {
            if (detail.operands[i].type == MIPS_OP_IMM) {
                return as_u64(detail.operands[i].imm);
            }
        }
        break;
    }
    case Family::Ppc: {
        const cs_ppc& detail = in.detail->ppc;
        for (std::uint8_t i = 0; i < detail.op_count; ++i) {
            if (detail.operands[i].type == PPC_OP_IMM) {
                return as_u64(detail.operands[i].imm);
            }
        }
        break;
    }
    case Family::RiscV: {
        const cs_riscv& detail = in.detail->riscv;
        for (std::uint8_t i = 0; i < detail.op_count; ++i) {
            if (detail.operands[i].type == RISCV_OP_IMM) {
                // Capstone reports RISC-V branch/jump immediates as PC-relative
                // offsets, unlike the absolute targets it produces for other ISAs.
                return in.address + as_u64(detail.operands[i].imm);
            }
        }
        break;
    }
    }
    return std::nullopt;
}

// Effective address of a data/memory operand, used to annotate string references.
// Implemented for x86 RIP-relative and absolute memory operands (the common case
// for string loads); other ISAs use multi-instruction address materialization and
// are left unresolved here.
[[nodiscard]] std::optional<std::uint64_t> data_reference(Architecture architecture, const cs_insn& in) noexcept {
    if (in.detail == nullptr || family_of(architecture) != Family::X86) {
        return std::nullopt;
    }
    const cs_x86& detail = in.detail->x86;
    for (std::uint8_t i = 0; i < detail.op_count; ++i) {
        if (detail.operands[i].type != X86_OP_MEM) {
            continue;
        }
        const x86_op_mem& mem = detail.operands[i].mem;
        if (mem.base == X86_REG_RIP) {
            return in.address + in.size + static_cast<std::uint64_t>(mem.disp);
        }
        if (mem.base == X86_REG_INVALID && mem.index == X86_REG_INVALID && mem.segment == X86_REG_INVALID &&
            mem.disp > 0) {
            return static_cast<std::uint64_t>(mem.disp);
        }
    }
    return std::nullopt;
}

constexpr std::size_t arm64_page_slots = 31; // X0..X30

int arm64_reg_index(arm64_reg reg) noexcept {
    if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) {
        return static_cast<int>(reg) - static_cast<int>(ARM64_REG_X0);
    }
    if (reg == ARM64_REG_X29) {
        return 29;
    }
    if (reg == ARM64_REG_X30) {
        return 30;
    }
    return -1;
}

// Track ADRP page bases per register and fold the following ADD/LDR offset so the
// effective data address of an ADRP+ADD (or ADRP+LDR) pair is recovered on ARM64,
// enabling string-reference annotation there.
void update_arm64_pairing(
    const cs_insn& in,
    std::array<std::optional<std::uint64_t>, arm64_page_slots>& page,
    std::optional<std::uint64_t>& reference_target) noexcept {
    if (in.detail == nullptr) {
        return;
    }
    const cs_arm64& detail = in.detail->arm64;

    if (in.id == ARM64_INS_ADRP) {
        if (detail.op_count >= 2 && detail.operands[0].type == ARM64_OP_REG &&
            detail.operands[1].type == ARM64_OP_IMM) {
            const int dest = arm64_reg_index(detail.operands[0].reg);
            if (dest >= 0) {
                page[static_cast<std::size_t>(dest)] = static_cast<std::uint64_t>(detail.operands[1].imm);
            }
        }
        return;
    }

    if (in.id == ARM64_INS_ADD && detail.op_count >= 3 && detail.operands[0].type == ARM64_OP_REG &&
        detail.operands[1].type == ARM64_OP_REG && detail.operands[2].type == ARM64_OP_IMM) {
        const int dest = arm64_reg_index(detail.operands[0].reg);
        const int base = arm64_reg_index(detail.operands[1].reg);
        if (base >= 0 && page[static_cast<std::size_t>(base)].has_value()) {
            const std::uint64_t effective =
                *page[static_cast<std::size_t>(base)] + static_cast<std::uint64_t>(detail.operands[2].imm);
            reference_target = effective;
            if (dest >= 0) {
                page[static_cast<std::size_t>(dest)] = effective;
            }
            return;
        }
    }

    if (in.id == ARM64_INS_LDR && detail.op_count >= 2 && detail.operands[1].type == ARM64_OP_MEM) {
        const int base = arm64_reg_index(detail.operands[1].mem.base);
        if (base >= 0 && page[static_cast<std::size_t>(base)].has_value()) {
            reference_target = *page[static_cast<std::size_t>(base)] +
                static_cast<std::uint64_t>(static_cast<std::int64_t>(detail.operands[1].mem.disp));
        }
    }

    // Conservatively invalidate any register this instruction writes.
    for (std::uint8_t i = 0; i < detail.op_count; ++i) {
        if (detail.operands[i].type == ARM64_OP_REG && (detail.operands[i].access & CS_AC_WRITE) != 0) {
            const int written = arm64_reg_index(detail.operands[i].reg);
            if (written >= 0) {
                page[static_cast<std::size_t>(written)].reset();
            }
        }
    }
}

[[nodiscard]] bool is_unconditional_jump(Architecture architecture, const cs_insn& in) noexcept {
    if (family_of(architecture) == Family::X86) {
        return in.id == X86_INS_JMP;
    }
    // Capstone emits the bare unconditional-branch mnemonic for these ISAs; any
    // conditional form carries a suffix (b.eq, beq, bdnz, ...) and will not match.
    const std::string_view mnemonic{in.mnemonic};
    return mnemonic == "b" || mnemonic == "j" || mnemonic == "ba";
}

[[nodiscard]] BranchKind classify_branch(Architecture architecture, const cs_insn& instruction) noexcept {
    if (has_group(instruction, CS_GRP_RET) || has_group(instruction, CS_GRP_IRET)) {
        return BranchKind::Return;
    }

    const bool has_target = direct_target(architecture, instruction).has_value();

    if (has_group(instruction, CS_GRP_CALL)) {
        return has_target ? BranchKind::Call : BranchKind::IndirectCall;
    }

    if (has_group(instruction, CS_GRP_JUMP)) {
        if (!has_target) {
            return BranchKind::IndirectJump;
        }
        return is_unconditional_jump(architecture, instruction)
            ? BranchKind::UnconditionalJump
            : BranchKind::ConditionalJump;
    }

    return BranchKind::None;
}

[[nodiscard]] Result<CodeBuffer> buffer_for_section(const elf::File& file, const elf::Section& section) {
    const std::optional<elf::SectionBytes> bytes = elf::section_bytes(file, section);
    if (!bytes.has_value()) {
        return Result<CodeBuffer>::err({
            ErrorCode::MalformedInput,
            "section bytes are outside the file image",
            section.offset,
            true,
        });
    }

    return Result<CodeBuffer>::ok({bytes->address, bytes->begin, bytes->end});
}

[[nodiscard]] std::optional<elf::Section> containing_executable_section(
    const elf::File& file,
    const elf::Symbol& symbol) {
    if (symbol.section_index != 0) {
        const auto by_index = std::find_if(
            file.sections.begin(),
            file.sections.end(),
            [&](const elf::Section& section) {
                return section.index == symbol.section_index && section.executable;
            });
        if (by_index != file.sections.end()) {
            return *by_index;
        }
    }

    const auto by_address = std::find_if(
        file.sections.begin(),
        file.sections.end(),
        [&](const elf::Section& section) {
            if (!section.executable || symbol.address < section.address) {
                return false;
            }
            const std::uint64_t offset = symbol.address - section.address;
            return offset < section.size;
        });

    if (by_address == file.sections.end()) {
        return std::nullopt;
    }

    return *by_address;
}

[[nodiscard]] Result<CodeBuffer> buffer_for_function(const elf::File& file, const elf::Symbol& symbol) {
    const std::optional<elf::Section> section = containing_executable_section(file, symbol);
    if (!section.has_value()) {
        return Result<CodeBuffer>::err({
            ErrorCode::NotFound,
            "function symbol is not contained in an executable section",
            symbol.address,
            true,
        });
    }

    if (symbol.address < section->address) {
        return Result<CodeBuffer>::err({
            ErrorCode::MalformedInput,
            "function symbol address precedes its section",
            symbol.address,
            true,
        });
    }

    Result<CodeBuffer> section_buffer = buffer_for_section(file, *section);
    if (!section_buffer) {
        return section_buffer;
    }

    CodeBuffer buffer = section_buffer.value();
    const std::uint64_t section_delta = symbol.address - section->address;
    if (section_delta > section->size) {
        return Result<CodeBuffer>::err({
            ErrorCode::MalformedInput,
            "function symbol starts past the end of its section",
            symbol.address,
            true,
        });
    }

    const std::uint64_t available = section->size - section_delta;
    const std::uint64_t requested = symbol.size == 0 ? available : symbol.size;
    if (requested > available) {
        return Result<CodeBuffer>::err({
            ErrorCode::MalformedInput,
            "function symbol size exceeds section bounds",
            symbol.address + available,
            true,
        });
    }

    if (section_delta > static_cast<std::uint64_t>(std::numeric_limits<std::ptrdiff_t>::max())
        || requested > static_cast<std::uint64_t>(std::numeric_limits<std::ptrdiff_t>::max())) {
        return Result<CodeBuffer>::err({ErrorCode::MalformedInput, "function byte range is too large"});
    }

    const auto start = buffer.begin + static_cast<std::ptrdiff_t>(section_delta);
    const auto stop = start + static_cast<std::ptrdiff_t>(requested);
    return Result<CodeBuffer>::ok({symbol.address, start, stop});
}

[[nodiscard]] std::vector<Instruction> trim_after_first_terminal(std::vector<Instruction> instructions) {
    const auto terminal = std::find_if(
        instructions.begin(),
        instructions.end(),
        [](const Instruction& instruction) { return is_terminal(instruction.branch_kind); });

    if (terminal != instructions.end()) {
        instructions.erase(terminal + 1, instructions.end());
    }

    return instructions;
}

} // namespace

Result<Options> options_for(binary::Architecture architecture, Syntax syntax) {
    Options options;
    options.syntax = syntax;
    options.resolve_branch_targets = true;

    switch (architecture) {
    case binary::Architecture::X86:
        options.architecture = Architecture::X86;
        break;
    case binary::Architecture::X86_64:
        options.architecture = Architecture::X86_64;
        break;
    case binary::Architecture::Arm:
        options.architecture = Architecture::Arm;
        break;
    case binary::Architecture::ArmThumb:
        options.architecture = Architecture::ArmThumb;
        break;
    case binary::Architecture::AArch64:
        options.architecture = Architecture::AArch64;
        break;
    case binary::Architecture::RiscV32:
        options.architecture = Architecture::RiscV32;
        break;
    case binary::Architecture::RiscV64:
        options.architecture = Architecture::RiscV64;
        break;
    case binary::Architecture::Mips32:
        options.architecture = Architecture::Mips32;
        break;
    case binary::Architecture::Mips32el:
        options.architecture = Architecture::Mips32el;
        break;
    case binary::Architecture::Mips64:
        options.architecture = Architecture::Mips64;
        break;
    case binary::Architecture::Mips64el:
        options.architecture = Architecture::Mips64el;
        break;
    case binary::Architecture::PowerPc32:
        options.architecture = Architecture::PowerPc32;
        break;
    case binary::Architecture::PowerPc64:
        options.architecture = Architecture::PowerPc64;
        break;
    case binary::Architecture::PowerPc64le:
        options.architecture = Architecture::PowerPc64le;
        break;
    case binary::Architecture::Unknown:
        return Result<Options>::err(
            {ErrorCode::UnsupportedFormat, "cannot disassemble an unknown architecture"});
    }

    return Result<Options>::ok(options);
}

Result<std::vector<Instruction>> disassemble_bytes(CodeBuffer code, const Options& options) {
    const auto distance = std::distance(code.begin, code.end);
    if (distance < 0) {
        return Result<std::vector<Instruction>>::err(
            {ErrorCode::MalformedInput, "code buffer iterators are reversed"});
    }

    if (distance == 0) {
        return Result<std::vector<Instruction>>::ok({});
    }

    Result<CapstoneHandle> engine = open_engine(options);
    if (!engine) {
        return Result<std::vector<Instruction>>::err(engine.error());
    }

    const auto byte_count = static_cast<std::size_t>(distance);
    cs_insn* raw_instructions = nullptr;
    const std::size_t decoded_count = cs_disasm(
        engine.value().get(),
        &(*code.begin),
        byte_count,
        code.address,
        0,
        &raw_instructions);
    InstructionBlock decoded(raw_instructions, decoded_count);

    if (decoded.count() == 0) {
        return Result<std::vector<Instruction>>::err({
            ErrorCode::Disassembly,
            "Capstone decoded no instructions from a non-empty buffer",
            code.address,
            true,
        });
    }

    std::vector<Instruction> instructions;
    instructions.reserve(decoded.count());
    std::array<std::optional<std::uint64_t>, arm64_page_slots> arm64_page{};

    for (const cs_insn& raw : decoded) {
        if (raw.size > static_cast<std::uint16_t>(std::numeric_limits<std::uint8_t>::max())) {
            return Result<std::vector<Instruction>>::err({
                ErrorCode::Disassembly,
                "Capstone returned an instruction size too large for roe's instruction model",
                raw.address,
                true,
            });
        }

        Instruction instruction;
        instruction.address = raw.address;
        instruction.size = static_cast<std::uint8_t>(raw.size);
        instruction.bytes.assign(raw.bytes, raw.bytes + raw.size);
        instruction.mnemonic = raw.mnemonic;
        instruction.operands = raw.op_str;
        instruction.branch_kind = classify_branch(options.architecture, raw);
        if (options.resolve_branch_targets && is_branch(instruction.branch_kind)) {
            instruction.branch_target = direct_target(options.architecture, raw);
        }
        instruction.reference_target = data_reference(options.architecture, raw);
        if (family_of(options.architecture) == Family::Arm64) {
            update_arm64_pairing(raw, arm64_page, instruction.reference_target);
        }
        instructions.push_back(std::move(instruction));
    }

    return Result<std::vector<Instruction>>::ok(std::move(instructions));
}

Result<std::vector<Instruction>> disassemble_function(
    const elf::File& file,
    const elf::Symbol& symbol,
    const Options& options) {
    Result<CodeBuffer> buffer = buffer_for_function(file, symbol);
    if (!buffer) {
        return Result<std::vector<Instruction>>::err(buffer.error());
    }

    Result<std::vector<Instruction>> instructions = disassemble_bytes(buffer.value(), options);
    if (!instructions || symbol.size != 0) {
        return instructions;
    }

    return Result<std::vector<Instruction>>::ok(trim_after_first_terminal(std::move(instructions).value()));
}

Result<std::vector<Instruction>> disassemble_section(
    const elf::File& file,
    const elf::Section& section,
    const Options& options) {
    if (!section.executable) {
        return Result<std::vector<Instruction>>::err(
            {ErrorCode::UnsupportedFormat, "section is not marked executable"});
    }

    Result<CodeBuffer> buffer = buffer_for_section(file, section);
    if (!buffer) {
        return Result<std::vector<Instruction>>::err(buffer.error());
    }

    return disassemble_bytes(buffer.value(), options);
}

Result<std::vector<Instruction>> disassemble_section(
    const binary::SectionBytes& section,
    const Options& options) {
    if (section.bytes.empty()) {
        return Result<std::vector<Instruction>>::ok({});
    }
    CodeBuffer code{section.address, section.bytes.begin(), section.bytes.end()};
    return disassemble_bytes(code, options);
}

Result<std::vector<Instruction>> disassemble_function(
    const binary::BinaryFile& file,
    const binary::Object& object,
    const binary::Symbol& symbol,
    const Options& options) {
    const std::optional<binary::Section> section = [&]() -> std::optional<binary::Section> {
        for (const binary::Section& candidate : object.sections) {
            if (!candidate.executable || symbol.address < candidate.address) {
                continue;
            }
            if (symbol.address - candidate.address < candidate.size) {
                return candidate;
            }
        }
        return std::nullopt;
    }();

    if (!section.has_value()) {
        return Result<std::vector<Instruction>>::err(
            {ErrorCode::NotFound, "function symbol is not contained in an executable section", symbol.address, true});
    }

    Result<binary::SectionBytes> section_bytes = file.section_bytes(*section);
    if (!section_bytes) {
        return Result<std::vector<Instruction>>::err(std::move(section_bytes).error());
    }

    const std::uint64_t delta = symbol.address - section->address;
    binary::SectionBytes& owned = section_bytes.value();
    if (delta > owned.bytes.size()) {
        return Result<std::vector<Instruction>>::err(
            {ErrorCode::MalformedInput, "function symbol starts past the end of its section", symbol.address, true});
    }
    const std::uint64_t available = owned.bytes.size() - delta;
    const std::uint64_t requested = symbol.size == 0 ? available : std::min(symbol.size, available);

    std::vector<std::uint8_t> window(
        owned.bytes.begin() + static_cast<std::ptrdiff_t>(delta),
        owned.bytes.begin() + static_cast<std::ptrdiff_t>(delta + requested));
    CodeBuffer code{symbol.address, window.begin(), window.end()};
    Result<std::vector<Instruction>> instructions = disassemble_bytes(code, options);
    if (!instructions || symbol.size != 0) {
        return instructions;
    }
    return Result<std::vector<Instruction>>::ok(trim_after_first_terminal(std::move(instructions).value()));
}

bool is_branch(BranchKind kind) noexcept {
    switch (kind) {
    case BranchKind::UnconditionalJump:
    case BranchKind::ConditionalJump:
    case BranchKind::Call:
    case BranchKind::Return:
    case BranchKind::IndirectJump:
    case BranchKind::IndirectCall:
        return true;
    case BranchKind::None:
        return false;
    }

    return false;
}

bool is_terminal(BranchKind kind) noexcept {
    switch (kind) {
    case BranchKind::UnconditionalJump:
    case BranchKind::Return:
    case BranchKind::IndirectJump:
        return true;
    case BranchKind::None:
    case BranchKind::ConditionalJump:
    case BranchKind::Call:
    case BranchKind::IndirectCall:
        return false;
    }

    return false;
}

} // namespace roe::disasm
