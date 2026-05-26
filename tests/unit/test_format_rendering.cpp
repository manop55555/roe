#include "roe/format.hpp"

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using roe::disasm::BranchKind;
using roe::disasm::Instruction;
using roe::resolver::AnnotatedInstruction;

void require(bool condition, const char* message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void require_contains(const std::string& text, const std::string& needle, const char* message)
{
    require(text.find(needle) != std::string::npos, message);
}

void require_not_contains(const std::string& text, const std::string& needle, const char* message)
{
    require(text.find(needle) == std::string::npos, message);
}

AnnotatedInstruction make_instruction(
    std::uint64_t address,
    std::vector<std::uint8_t> bytes,
    std::string mnemonic,
    std::string operands = {},
    BranchKind branch_kind = BranchKind::None)
{
    AnnotatedInstruction annotated;
    annotated.instruction.address = address;
    annotated.instruction.size = static_cast<std::uint8_t>(bytes.size());
    annotated.instruction.bytes = std::move(bytes);
    annotated.instruction.mnemonic = std::move(mnemonic);
    annotated.instruction.operands = std::move(operands);
    annotated.instruction.branch_kind = branch_kind;
    return annotated;
}

void test_color_suppression()
{
    const char* previous_no_color = std::getenv("NO_COLOR");
    const std::string previous_no_color_text = previous_no_color == nullptr ? "" : previous_no_color;

    roe::format::Options colored;
    colored.color = true;
    colored.no_color_env = false;
    require(roe::format::color_enabled(colored), "color should be enabled by default options");

    roe::format::Options explicit_no_color = colored;
    explicit_no_color.color = false;
    require(!roe::format::color_enabled(explicit_no_color), "--no-color should suppress color");

    roe::format::Options env_no_color = colored;
    env_no_color.no_color_env = true;
    require(!roe::format::color_enabled(env_no_color), "NO_COLOR should suppress color");

    roe::Error error{roe::ErrorCode::Usage, "bad args", 0, false};
    const std::string rendered = roe::format::render_error(error, explicit_no_color).value();
    require_not_contains(rendered, "\033[", "render_error should omit ANSI color when disabled");

    require(unsetenv("NO_COLOR") == 0, "unsetenv should succeed");
    require(!roe::format::default_options().no_color_env, "default_options should read absent NO_COLOR");
    require(setenv("NO_COLOR", "1", 1) == 0, "setenv should succeed");
    require(roe::format::default_options().no_color_env, "default_options should read present NO_COLOR");

    if (previous_no_color == nullptr) {
        require(unsetenv("NO_COLOR") == 0, "NO_COLOR restore unset should succeed");
    } else {
        require(setenv("NO_COLOR", previous_no_color_text.c_str(), 1) == 0, "NO_COLOR restore should succeed");
    }
}

void test_function_list_preserves_addresses()
{
    roe::elf::File file;
    file.source_name = "fixture.o";
    file.symbols.push_back({"beta", 0x42, 8, 1, roe::elf::SymbolBind::Global, roe::elf::SymbolType::Function, true, false});
    file.symbols.push_back({"alpha", 0x10, 4, 1, roe::elf::SymbolBind::Global, roe::elf::SymbolType::Function, true, false});
    file.symbols.push_back({"data", 0x20, 4, 1, roe::elf::SymbolBind::Global, roe::elf::SymbolType::Object, true, false});

    roe::format::Options options;
    options.color = false;
    const std::string rendered = roe::format::render_function_list(file, roe::resolver::Index{}, options).value();
    require_contains(rendered, "0x0000000000000010", "function list should preserve alpha address");
    require_contains(rendered, "0x0000000000000042", "function list should preserve beta address");
    require_not_contains(rendered, "data", "function list should omit non-function symbols");
}

void test_function_list_uses_resolver_display_names()
{
    roe::elf::File file;
    file.source_name = "fixture";
    file.symbols.push_back({"_ZN7fixture6Worker7computeEi", 0x21aa, 33, 1, roe::elf::SymbolBind::Global, roe::elf::SymbolType::Function, true, false});

    roe::resolver::Index index;
    index.symbols.push_back({
        "fixture::Worker::compute(int)",
        "_ZN7fixture6Worker7computeEi",
        0x21aa,
        33,
        false,
        false});

    roe::format::Options options;
    options.color = false;
    const std::string rendered = roe::format::render_function_list(file, index, options).value();
    require_contains(rendered, "fixture::Worker::compute(int)", "function list should prefer resolver display names");
    require_not_contains(rendered, "_ZN7fixture6Worker7computeEi", "function list should not expose raw names when display name is available");
}

void test_branch_labels_and_inline_previews()
{
    std::vector<AnnotatedInstruction> instructions;
    AnnotatedInstruction earlier_target = make_instruction(0x20, {0x90}, "nop");
    AnnotatedInstruction branch = make_instruction(
        0x30,
        {0x74, 0x03},
        "je",
        "0x35",
        BranchKind::ConditionalJump);
    branch.instruction.branch_target = 0x35;
    AnnotatedInstruction backward_branch = make_instruction(
        0x40,
        {0x75, 0xde},
        "jne",
        "0x20",
        BranchKind::ConditionalJump);
    backward_branch.instruction.branch_target = 0x20;
    instructions.push_back(earlier_target);
    instructions.push_back(branch);
    instructions.push_back(make_instruction(0x32, {0x31, 0xdb}, "xor", "ebx, ebx"));
    instructions.push_back(make_instruction(0x35, {0x31, 0xc0}, "xor", "eax, eax"));
    instructions.push_back(backward_branch);

    roe::format::Options options;
    options.color = false;
    const std::string rendered = roe::format::render_disassembly(instructions, options).value();
    require_contains(rendered, "jne 0x20 \u2192 [L1: nop]", "lower target should receive the first stable label");
    require_contains(rendered, "je 0x35 \u2192 [L2: xor eax, eax]", "branch preview should be inline");
    require_contains(rendered, "L2:\n0x0000000000000035", "branch target should receive stable label");
    require_not_contains(rendered, "\n→", "formatter should not draw separate arrow lines");
}

void test_json_escaping_and_references()
{
    std::vector<AnnotatedInstruction> instructions;
    AnnotatedInstruction annotated = make_instruction(0x100, {0xe8, 0x00}, "call", "puts \"x\"\n");
    annotated.reference = roe::resolver::ResolvedReference{
        0x101,
        "puts\tplt",
        "puts@GLIBC_2.2.5",
        ".rela.plt",
        7,
        -4,
        true};
    instructions.push_back(annotated);

    roe::format::Options options;
    const std::string rendered = roe::format::render_json(instructions, options).value();
    require_contains(rendered, "\"address\": \"0x100\"", "JSON should preserve instruction address as hex text");
    require_contains(rendered, "\"operands\": \"puts \\\"x\\\"\\n\"", "JSON should escape quotes and newlines");
    require_contains(rendered, "\"name\":\"puts\\tplt\"", "JSON should escape reference tabs");
    require_contains(rendered, "\"addend\":-4", "JSON should include relocation addend");
}

void test_banner_and_help()
{
    const std::string banner = roe::format::render_banner().value();
    require_contains(banner, "roe 0.1.0", "banner should include program version");
    require_contains(banner, "Readable object explorer", "banner should include short description");

    const std::string help = roe::format::render_help().value();
    require_contains(help, "roe <file> <symbol>", "help should document symbol disassembly");
    require_contains(help, "--section <name>", "help should document section disassembly");
    require_contains(help, "--json", "help should document JSON output");
    require_contains(help, "--no-color", "help should document color suppression");
}

} // namespace

int main()
{
    const std::vector<void (*)()> tests{
        test_color_suppression,
        test_function_list_preserves_addresses,
        test_function_list_uses_resolver_display_names,
        test_branch_labels_and_inline_previews,
        test_json_escaping_and_references,
        test_banner_and_help,
    };

    try {
        for (void (*test)() : tests) {
            test();
        }
    } catch (const std::exception& error) {
        std::cerr << "test_format_rendering failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
