#include "roe/disasm.hpp"

#include <capstone/capstone.h>
#include <capstone/x86.h>

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <limits>
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

Result<CapstoneHandle> open_engine(const Options& options) {
    if (options.architecture == Architecture::AArch64) {
        return Result<CapstoneHandle>::err(
            {ErrorCode::UnsupportedFormat, "AArch64 disassembly is not implemented yet"});
    }

    csh raw_handle = 0;
    const cs_err open_result = cs_open(CS_ARCH_X86, CS_MODE_64, &raw_handle);
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

    if (options.syntax == Syntax::Att) {
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

[[nodiscard]] bool first_x86_operand_is_immediate(const cs_insn& instruction) noexcept {
    if (instruction.detail == nullptr) {
        return false;
    }

    const cs_x86& x86 = instruction.detail->x86;
    return x86.op_count > 0 && x86.operands[0].type == X86_OP_IMM;
}

[[nodiscard]] std::optional<std::uint64_t> direct_x86_target(const cs_insn& instruction) noexcept {
    if (!first_x86_operand_is_immediate(instruction)) {
        return std::nullopt;
    }

    const std::int64_t target = instruction.detail->x86.operands[0].imm;
    return static_cast<std::uint64_t>(target);
}

[[nodiscard]] BranchKind classify_x86_branch(const cs_insn& instruction) noexcept {
    if (has_group(instruction, CS_GRP_RET) || has_group(instruction, CS_GRP_IRET)) {
        return BranchKind::Return;
    }

    if (has_group(instruction, CS_GRP_CALL)) {
        return first_x86_operand_is_immediate(instruction) ? BranchKind::Call : BranchKind::IndirectCall;
    }

    if (has_group(instruction, CS_GRP_JUMP)) {
        if (instruction.id == X86_INS_JMP) {
            return first_x86_operand_is_immediate(instruction)
                ? BranchKind::UnconditionalJump
                : BranchKind::IndirectJump;
        }
        return BranchKind::ConditionalJump;
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
        instruction.branch_kind = classify_x86_branch(raw);
        if (options.resolve_branch_targets && is_branch(instruction.branch_kind)) {
            instruction.branch_target = direct_x86_target(raw);
        }
        instructions.push_back(std::move(instruction));
    }

    return Result<std::vector<Instruction>>::ok(std::move(instructions));
}

Result<std::vector<Instruction>> disassemble_function(
    const elf::File& file,
    const elf::Symbol& symbol,
    const Options& options) {
    if (file.machine == elf::Machine::AArch64 || options.architecture == Architecture::AArch64) {
        return Result<std::vector<Instruction>>::err(
            {ErrorCode::UnsupportedFormat, "AArch64 disassembly is not implemented yet"});
    }

    if (file.machine != elf::Machine::X86_64) {
        return Result<std::vector<Instruction>>::err(
            {ErrorCode::UnsupportedFormat, "only x86-64 ELF disassembly is implemented"});
    }

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
    if (file.machine == elf::Machine::AArch64 || options.architecture == Architecture::AArch64) {
        return Result<std::vector<Instruction>>::err(
            {ErrorCode::UnsupportedFormat, "AArch64 disassembly is not implemented yet"});
    }

    if (file.machine != elf::Machine::X86_64) {
        return Result<std::vector<Instruction>>::err(
            {ErrorCode::UnsupportedFormat, "only x86-64 ELF disassembly is implemented"});
    }

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
