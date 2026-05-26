#include "roe/disasm.hpp"

#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

namespace roe::elf {

std::optional<SectionBytes> section_bytes(const File& file, const Section& section) __attribute__((weak));

std::optional<SectionBytes> section_bytes(const File& file, const Section& section) {
    if (section.offset > static_cast<std::uint64_t>(file.image.size())) {
        return std::nullopt;
    }
    if (section.size > static_cast<std::uint64_t>(file.image.size()) - section.offset) {
        return std::nullopt;
    }

    const auto start = file.image.begin() + static_cast<std::ptrdiff_t>(section.offset);
    const auto stop = start + static_cast<std::ptrdiff_t>(section.size);
    return SectionBytes{section.address, start, stop};
}

} // namespace roe::elf

namespace {

struct TestContext {
    int failures{0};

    void require(bool condition, const char* expression, int line) {
        if (!condition) {
            ++failures;
            std::cerr << "line " << line << ": requirement failed: " << expression << '\n';
        }
    }
};

#define REQUIRE_CTX(ctx, expr) (ctx).require((expr), #expr, __LINE__)

roe::disasm::CodeBuffer buffer_for(std::vector<std::uint8_t>& bytes, std::uint64_t address = 0x1000) {
    return roe::disasm::CodeBuffer{address, bytes.begin(), bytes.end()};
}

void test_empty_and_malformed_buffers(TestContext& ctx) {
    roe::disasm::Options options;

    std::vector<std::uint8_t> empty;
    const auto empty_result = roe::disasm::disassemble_bytes(buffer_for(empty), options);
    REQUIRE_CTX(ctx, empty_result.has_value());
    REQUIRE_CTX(ctx, empty_result.value().empty());

    std::vector<std::uint8_t> malformed{0xff};
    const auto malformed_result = roe::disasm::disassemble_bytes(buffer_for(malformed), options);
    REQUIRE_CTX(ctx, !malformed_result.has_value());
    REQUIRE_CTX(ctx, malformed_result.error().code == roe::ErrorCode::Disassembly);
}

void test_branch_classification_and_targets(TestContext& ctx) {
    roe::disasm::Options options;
    std::vector<std::uint8_t> bytes{
        0x74, 0x03,                   // je 0x1005
        0xe8, 0x10, 0x00, 0x00, 0x00, // call 0x1017
        0xff, 0xe0,                   // jmp rax
        0xc3,                         // ret
    };

    const auto result = roe::disasm::disassemble_bytes(buffer_for(bytes), options);
    REQUIRE_CTX(ctx, result.has_value());
    const auto& instructions = result.value();
    REQUIRE_CTX(ctx, instructions.size() == 4);

    REQUIRE_CTX(ctx, instructions[0].branch_kind == roe::disasm::BranchKind::ConditionalJump);
    REQUIRE_CTX(ctx, instructions[0].branch_target.has_value());
    REQUIRE_CTX(ctx, instructions[0].branch_target.value() == 0x1005);

    REQUIRE_CTX(ctx, instructions[1].branch_kind == roe::disasm::BranchKind::Call);
    REQUIRE_CTX(ctx, instructions[1].branch_target.has_value());
    REQUIRE_CTX(ctx, instructions[1].branch_target.value() == 0x1017);

    REQUIRE_CTX(ctx, instructions[2].branch_kind == roe::disasm::BranchKind::IndirectJump);
    REQUIRE_CTX(ctx, !instructions[2].branch_target.has_value());

    REQUIRE_CTX(ctx, instructions[3].branch_kind == roe::disasm::BranchKind::Return);
    REQUIRE_CTX(ctx, roe::disasm::is_branch(instructions[3].branch_kind));
    REQUIRE_CTX(ctx, roe::disasm::is_terminal(instructions[3].branch_kind));
    REQUIRE_CTX(ctx, !roe::disasm::is_terminal(roe::disasm::BranchKind::Call));
}

void test_section_slicing(TestContext& ctx) {
    roe::elf::File file;
    file.machine = roe::elf::Machine::X86_64;
    file.image = {
        0x90,
        0x90,
        0x74, 0x01,
        0xc3,
        0x90,
    };

    roe::elf::Section text;
    text.name = ".text";
    text.index = 1;
    text.address = 0x4000;
    text.offset = 2;
    text.size = 3;
    text.executable = true;

    const auto result = roe::disasm::disassemble_section(file, text, roe::disasm::Options{});
    REQUIRE_CTX(ctx, result.has_value());
    const auto& instructions = result.value();
    REQUIRE_CTX(ctx, instructions.size() == 2);
    REQUIRE_CTX(ctx, instructions[0].address == 0x4000);
    REQUIRE_CTX(ctx, instructions[0].branch_target.has_value());
    REQUIRE_CTX(ctx, instructions[0].branch_target.value() == 0x4003);
    REQUIRE_CTX(ctx, instructions[1].address == 0x4002);
    REQUIRE_CTX(ctx, instructions[1].branch_kind == roe::disasm::BranchKind::Return);
}

void test_function_slicing(TestContext& ctx) {
    roe::elf::File file;
    file.machine = roe::elf::Machine::X86_64;
    file.image = {
        0x90,
        0x55,
        0x48, 0x89, 0xe5,
        0xc3,
        0x90,
        0xc3,
    };

    roe::elf::Section text;
    text.name = ".text";
    text.index = 7;
    text.address = 0x5000;
    text.offset = 1;
    text.size = 7;
    text.executable = true;
    file.sections.push_back(text);

    roe::elf::Symbol sized;
    sized.name = "sized";
    sized.address = 0x5000;
    sized.size = 5;
    sized.section_index = text.index;
    sized.type = roe::elf::SymbolType::Function;
    sized.defined = true;

    const auto sized_result = roe::disasm::disassemble_function(file, sized, roe::disasm::Options{});
    REQUIRE_CTX(ctx, sized_result.has_value());
    REQUIRE_CTX(ctx, sized_result.value().size() == 3);
    REQUIRE_CTX(ctx, sized_result.value().back().branch_kind == roe::disasm::BranchKind::Return);

    roe::elf::Symbol unsized = sized;
    unsized.name = "unsized";
    unsized.address = 0x5005;
    unsized.size = 0;

    const auto unsized_result = roe::disasm::disassemble_function(file, unsized, roe::disasm::Options{});
    REQUIRE_CTX(ctx, unsized_result.has_value());
    REQUIRE_CTX(ctx, unsized_result.value().size() == 2);
    REQUIRE_CTX(ctx, unsized_result.value().front().address == 0x5005);
    REQUIRE_CTX(ctx, unsized_result.value().back().branch_kind == roe::disasm::BranchKind::Return);
}

} // namespace

int main() {
    TestContext ctx;
    test_empty_and_malformed_buffers(ctx);
    test_branch_classification_and_targets(ctx);
    test_section_slicing(ctx);
    test_function_slicing(ctx);

    if (ctx.failures != 0) {
        std::cerr << ctx.failures << " disasm test failure(s)\n";
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
