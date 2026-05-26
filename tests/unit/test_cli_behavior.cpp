#include "roe/cli.hpp"

#include "roe/disasm.hpp"
#include "roe/elf.hpp"
#include "roe/format.hpp"
#include "roe/resolver.hpp"
#include "roe/version.hpp"

#include <cstdlib>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#if !defined(ROE_CLI_STANDALONE) && __has_include(<catch2/catch_test_macros.hpp>)
#include <catch2/catch_test_macros.hpp>
#define ROE_TEST_CASE(name) TEST_CASE(name)
#define ROE_CHECK(condition) CHECK(condition)
#define ROE_REQUIRE(condition) REQUIRE(condition)
#else
#include <iostream>
#define ROE_TEST_CASE(name) static void name()
#define ROE_CHECK(condition)                                                                                              \
    do {                                                                                                                  \
        if (!(condition)) {                                                                                               \
            std::cerr << "check failed: " #condition << " at " << __FILE__ << ':' << __LINE__ << '\n';                  \
            std::abort();                                                                                                 \
        }                                                                                                                 \
    } while (false)
#define ROE_REQUIRE(condition) ROE_CHECK(condition)
#endif

namespace roe::format {

Options default_options()
{
    return {};
}

bool color_enabled(const Options& options) noexcept
{
    return options.color && !options.no_color_env;
}

Result<std::string> render_banner()
{
    return Result<std::string>::ok(std::string{program_name} + " v" + version_string + "\nY-Y");
}

Result<std::string> render_help()
{
    return Result<std::string>::ok("Y-Y\nusage: roe <file> [symbol] [--section <name>] [--json] [--no-color] [--show-bytes]");
}

Result<std::string> render_error(const Error& error, const Options&)
{
    return Result<std::string>::ok("error: " + error.message);
}

Result<std::string> render_function_list(const elf::File&, const resolver::Index&, const Options& options)
{
    return Result<std::string>::ok(color_enabled(options) ? "functions-color" : "functions-no-color");
}

Result<std::string> render_disassembly(
    const std::vector<resolver::AnnotatedInstruction>&,
    const Options& options)
{
    return Result<std::string>::ok(color_enabled(options) ? "disassembly-color" : "disassembly-no-color");
}

Result<std::string> render_json(const std::vector<resolver::AnnotatedInstruction>&, const Options&)
{
    return Result<std::string>::ok("{\"instructions\":[]}");
}

} // namespace roe::format

namespace roe::elf {

Result<File> parse_file(const std::filesystem::path& path)
{
    if (path == "missing") {
        return Result<File>::err(Error{ErrorCode::FileIo, "cannot read file", 0, false});
    }
    if (path == "bad-elf") {
        return Result<File>::err(Error{ErrorCode::MalformedInput, "not an ELF file", 0, false});
    }

    File file;
    file.source_name = path.string();
    file.machine = Machine::X86_64;
    file.sections.push_back(Section{".text", 1, 0, 0, 0x1000, 0, 16, 1, true});
    file.symbols.push_back(Symbol{"main", 0x1000, 4, 1, SymbolBind::Global, SymbolType::Function, true, false});
    return Result<File>::ok(std::move(file));
}

Result<File> parse_bytes(std::string, std::vector<std::uint8_t>)
{
    return Result<File>::err(Error{ErrorCode::Internal, "unused", 0, false});
}

std::optional<Section> find_section(const File& file, std::string_view name)
{
    for (const Section& section : file.sections) {
        if (section.name == name) {
            return section;
        }
    }
    return std::nullopt;
}

std::vector<Symbol> function_symbols(const File& file)
{
    return file.symbols;
}

std::optional<Symbol> find_symbol(const File& file, std::string_view name)
{
    for (const Symbol& symbol : file.symbols) {
        if (symbol.name == name) {
            return symbol;
        }
    }
    return std::nullopt;
}

std::optional<SectionBytes> section_bytes(const File&, const Section&)
{
    return std::nullopt;
}

} // namespace roe::elf

namespace roe::resolver {

Result<Index> build_index(const elf::File& file, const Options&)
{
    if (file.source_name == "bad-resolver") {
        return Result<Index>::err(Error{ErrorCode::Resolution, "resolver failed", 0, false});
    }
    return Result<Index>::ok(Index{});
}

std::optional<ResolvedSymbol> symbol_at(const Index&, std::uint64_t)
{
    return std::nullopt;
}

std::optional<ResolvedSymbol> nearest_symbol(const Index&, std::uint64_t)
{
    return std::nullopt;
}

std::optional<ResolvedReference> relocation_at(const Index&, std::uint64_t)
{
    return std::nullopt;
}

std::vector<AnnotatedInstruction> annotate(const Index&, const std::vector<disasm::Instruction>& instructions)
{
    std::vector<AnnotatedInstruction> annotated;
    for (const disasm::Instruction& instruction : instructions) {
        annotated.push_back(AnnotatedInstruction{instruction, std::nullopt, std::nullopt, std::nullopt});
    }
    return annotated;
}

std::string demangle(std::string_view name)
{
    return std::string{name};
}

} // namespace roe::resolver

namespace roe::disasm {

Result<std::vector<Instruction>> disassemble_bytes(CodeBuffer, const Options&)
{
    return Result<std::vector<Instruction>>::err(Error{ErrorCode::Internal, "unused", 0, false});
}

Result<std::vector<Instruction>> disassemble_function(const elf::File&, const elf::Symbol&, const Options&)
{
    return Result<std::vector<Instruction>>::ok(
        std::vector<Instruction>{Instruction{0x1000, 1, {0xc3}, "ret", "", BranchKind::Return, std::nullopt}});
}

Result<std::vector<Instruction>> disassemble_section(const elf::File&, const elf::Section&, const Options&)
{
    return Result<std::vector<Instruction>>::ok(
        std::vector<Instruction>{Instruction{0x1000, 1, {0xc3}, "ret", "", BranchKind::Return, std::nullopt}});
}

bool is_branch(BranchKind kind) noexcept
{
    return kind != BranchKind::None;
}

bool is_terminal(BranchKind kind) noexcept
{
    return kind == BranchKind::Return || kind == BranchKind::UnconditionalJump || kind == BranchKind::IndirectJump;
}

} // namespace roe::disasm

namespace {

std::vector<char*> argv_from(std::vector<std::string>& args)
{
    std::vector<char*> argv;
    for (std::string& arg : args) {
        argv.push_back(arg.data());
    }
    return argv;
}

roe::Result<roe::cli::Arguments> parse(std::vector<std::string> args)
{
    std::vector<char*> argv = argv_from(args);
    return roe::cli::parse_args(static_cast<int>(argv.size()), argv.data());
}

} // namespace

ROE_TEST_CASE(test_cli_parse_args_common_forms)
{
    {
        roe::Result<roe::cli::Arguments> args = parse({"roe", "sample"});
        ROE_REQUIRE(args.has_value());
        ROE_CHECK(args.value().action == roe::cli::Action::ListFunctions);
        ROE_REQUIRE(args.value().file.has_value());
        ROE_CHECK(args.value().file.value() == "sample");
    }
    {
        roe::Result<roe::cli::Arguments> args = parse({"roe", "sample", "main", "--json", "--no-color", "--show-bytes"});
        ROE_REQUIRE(args.has_value());
        ROE_CHECK(args.value().action == roe::cli::Action::DisassembleSymbol);
        ROE_REQUIRE(args.value().symbol.has_value());
        ROE_CHECK(args.value().symbol.value() == "main");
        ROE_CHECK(args.value().json);
        ROE_CHECK(args.value().no_color);
        ROE_CHECK(args.value().show_bytes);
    }
    {
        roe::Result<roe::cli::Arguments> args = parse({"roe", "sample", "--section", ".text"});
        ROE_REQUIRE(args.has_value());
        ROE_CHECK(args.value().action == roe::cli::Action::DisassembleSection);
        ROE_REQUIRE(args.value().section.has_value());
        ROE_CHECK(args.value().section.value() == ".text");
    }
}

ROE_TEST_CASE(test_cli_parse_args_errors)
{
    ROE_CHECK(!parse({"roe", "sample", "--unknown"}).has_value());
    ROE_CHECK(!parse({"roe", "sample", "--section"}).has_value());
    ROE_CHECK(!parse({"roe", "sample", "main", "--section=.text"}).has_value());
    ROE_CHECK(!parse({"roe", "sample", "--json"}).has_value());
}

ROE_TEST_CASE(test_cli_main_entry_common_cases)
{
    static_cast<void>(::unsetenv("NO_COLOR"));

    {
        std::vector<std::string> args{"roe", "--help"};
        std::vector<char*> argv = argv_from(args);
        std::ostringstream out;
        std::ostringstream err;
        const int code = roe::cli::main_entry(static_cast<int>(argv.size()), argv.data(), out, err);
        ROE_CHECK(code == roe::cli::exit_ok);
        ROE_CHECK(out.str().find("usage: roe") != std::string::npos);
        ROE_CHECK(err.str().empty());
    }
    {
        std::vector<std::string> args{"roe", "--version"};
        std::vector<char*> argv = argv_from(args);
        std::ostringstream out;
        std::ostringstream err;
        const int code = roe::cli::main_entry(static_cast<int>(argv.size()), argv.data(), out, err);
        ROE_CHECK(code == roe::cli::exit_ok);
        ROE_CHECK(out.str().find("0.1.0") != std::string::npos);
    }
    {
        std::vector<std::string> args{"roe", "sample"};
        std::vector<char*> argv = argv_from(args);
        std::ostringstream out;
        std::ostringstream err;
        const int code = roe::cli::main_entry(static_cast<int>(argv.size()), argv.data(), out, err);
        ROE_CHECK(code == roe::cli::exit_ok);
        ROE_CHECK(out.str().find("functions-color") != std::string::npos);
    }
    {
        static_cast<void>(::setenv("NO_COLOR", "1", 1));
        std::vector<std::string> args{"roe", "sample"};
        std::vector<char*> argv = argv_from(args);
        std::ostringstream out;
        std::ostringstream err;
        const int code = roe::cli::main_entry(static_cast<int>(argv.size()), argv.data(), out, err);
        ROE_CHECK(code == roe::cli::exit_ok);
        ROE_CHECK(out.str().find("functions-no-color") != std::string::npos);
        static_cast<void>(::unsetenv("NO_COLOR"));
    }
    {
        std::vector<std::string> args{"roe", "sample", "--no-color"};
        std::vector<char*> argv = argv_from(args);
        std::ostringstream out;
        std::ostringstream err;
        const int code = roe::cli::main_entry(static_cast<int>(argv.size()), argv.data(), out, err);
        ROE_CHECK(code == roe::cli::exit_ok);
        ROE_CHECK(out.str().find("functions-no-color") != std::string::npos);
    }
    {
        std::vector<std::string> args{"roe", "sample", "main", "--json"};
        std::vector<char*> argv = argv_from(args);
        std::ostringstream out;
        std::ostringstream err;
        const int code = roe::cli::main_entry(static_cast<int>(argv.size()), argv.data(), out, err);
        ROE_CHECK(code == roe::cli::exit_ok);
        ROE_CHECK(out.str().find("\"instructions\"") != std::string::npos);
    }
}

ROE_TEST_CASE(test_cli_main_entry_error_cases)
{
    {
        std::vector<std::string> args{"roe", "missing"};
        std::vector<char*> argv = argv_from(args);
        std::ostringstream out;
        std::ostringstream err;
        const int code = roe::cli::main_entry(static_cast<int>(argv.size()), argv.data(), out, err);
        ROE_CHECK(code == roe::cli::exit_file_error);
        ROE_CHECK(out.str().empty());
        ROE_CHECK(err.str().find("cannot read file") != std::string::npos);
    }
    {
        std::vector<std::string> args{"roe", "sample", "not_there"};
        std::vector<char*> argv = argv_from(args);
        std::ostringstream out;
        std::ostringstream err;
        const int code = roe::cli::main_entry(static_cast<int>(argv.size()), argv.data(), out, err);
        ROE_CHECK(code == roe::cli::exit_disasm_error);
        ROE_CHECK(err.str().find("symbol 'not_there' not found in sample") != std::string::npos);
        ROE_CHECK(err.str().find("not found: symbol not found") == std::string::npos);
    }
    {
        std::vector<std::string> args{"roe", "sample", "--bad"};
        std::vector<char*> argv = argv_from(args);
        std::ostringstream out;
        std::ostringstream err;
        const int code = roe::cli::main_entry(static_cast<int>(argv.size()), argv.data(), out, err);
        ROE_CHECK(code == roe::cli::exit_usage);
        ROE_CHECK(err.str().find("unknown option") != std::string::npos);
    }
}

#if defined(ROE_CLI_STANDALONE) || !__has_include(<catch2/catch_test_macros.hpp>)
int main()
{
    test_cli_parse_args_common_forms();
    test_cli_parse_args_errors();
    test_cli_main_entry_common_cases();
    test_cli_main_entry_error_cases();
    return 0;
}
#endif
