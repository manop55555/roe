#include "roe/cli.hpp"

#include "roe/disasm.hpp"
#include "roe/elf.hpp"
#include "roe/format.hpp"
#include "roe/resolver.hpp"
#include "roe/version.hpp"

#include <cstdlib>
#include <ostream>
#include <string_view>
#include <vector>

namespace roe::cli {
namespace {

Error usage_error(std::string message)
{
    return Error{ErrorCode::Usage, std::move(message), 0, false};
}

Error internal_error(std::string message)
{
    return Error{ErrorCode::Internal, std::move(message), 0, false};
}

bool is_flag(std::string_view argument) noexcept
{
    return argument.size() > 1 && argument[0] == '-';
}

bool no_color_env_set() noexcept
{
    return std::getenv("NO_COLOR") != nullptr;
}

format::Options format_options(const Arguments& parsed) noexcept
{
    format::Options options = format::default_options();
    options.mode = parsed.json ? format::Mode::Json : format::Mode::Text;
    options.no_color_env = no_color_env_set();
    options.color = !parsed.no_color && !options.no_color_env;
    options.preserve_addresses = true;
    options.show_bytes = parsed.show_bytes;
    return options;
}

void write_line(std::ostream& stream, std::string_view text)
{
    stream << text;
    if (text.empty() || text.back() != '\n') {
        stream << '\n';
    }
}

void write_error(std::ostream& stream, const Error& error, const format::Options& options)
{
    const Result<std::string> rendered = format::render_error(error, options);
    if (rendered) {
        write_line(stream, rendered.value());
        return;
    }

    stream << program_name << ": error: " << error.message;
    if (error.has_offset) {
        stream << " at offset 0x" << std::hex << error.offset << std::dec;
    }
    stream << '\n';
}

void write_missing_symbol_error(
    std::ostream& stream,
    std::string_view symbol,
    const elf::File& file)
{
    stream << "error: symbol '" << symbol << "' not found in " << file.source_name << "\n";
    if (file.stripped) {
        stream << "\n";
        stream << "hint: the binary is stripped (.symtab is absent). try:\n";
        stream << "  - using an unstripped binary, or\n";
        stream << "  - listing available dynamic symbols: roe " << file.source_name << "\n";
    }
}

int write_rendered(Result<std::string> rendered, std::ostream& out, std::ostream& err, const format::Options& options)
{
    if (!rendered) {
        write_error(err, rendered.error(), options);
        return exit_disasm_error;
    }

    write_line(out, rendered.value());
    return exit_ok;
}

int disassembly_exit_for(const ErrorCode code) noexcept
{
    switch (code) {
    case ErrorCode::FileIo:
    case ErrorCode::MalformedInput:
    case ErrorCode::UnsupportedFormat:
        return exit_file_error;
    default:
        return exit_disasm_error;
    }
}

disasm::Options disasm_options_for(const elf::File& file) noexcept
{
    disasm::Options options;
    if (file.machine == elf::Machine::AArch64) {
        options.architecture = disasm::Architecture::AArch64;
    } else {
        options.architecture = disasm::Architecture::X86_64;
    }
    options.syntax = disasm::Syntax::Intel;
    options.resolve_branch_targets = true;
    return options;
}

Result<std::string> render_annotated(
    const std::vector<resolver::AnnotatedInstruction>& annotated,
    const Arguments& parsed,
    const format::Options& options)
{
    if (parsed.json) {
        return format::render_json(annotated, options);
    }
    return format::render_disassembly(annotated, options);
}

} // namespace

Result<Arguments> parse_args(int argc, char** argv)
{
    if (argc < 0 || (argc > 0 && argv == nullptr)) {
        return Result<Arguments>::err(usage_error("invalid argv"));
    }

    Arguments parsed;
    std::vector<std::string> positional;

    for (int index = 1; index < argc; ++index) {
        if (argv[index] == nullptr) {
            return Result<Arguments>::err(usage_error("invalid null argument"));
        }

        const std::string_view argument{argv[index]};
        if (argument == "--help" || argument == "-h") {
            parsed.action = Action::ShowHelp;
            return Result<Arguments>::ok(std::move(parsed));
        }
        if (argument == "--version" || argument == "-V") {
            parsed.action = Action::ShowVersion;
            return Result<Arguments>::ok(std::move(parsed));
        }
        if (argument == "--no-color") {
            parsed.no_color = true;
            continue;
        }
        if (argument == "--json") {
            parsed.json = true;
            continue;
        }
        if (argument == "--show-bytes") {
            parsed.show_bytes = true;
            continue;
        }
        if (argument == "--section") {
            if (index + 1 >= argc || argv[index + 1] == nullptr || is_flag(argv[index + 1])) {
                return Result<Arguments>::err(usage_error("--section requires a section name"));
            }
            parsed.section = argv[index + 1];
            ++index;
            continue;
        }
        constexpr std::string_view section_prefix{"--section="};
        if (argument.substr(0, section_prefix.size()) == section_prefix) {
            const std::string_view section_name = argument.substr(section_prefix.size());
            if (section_name.empty()) {
                return Result<Arguments>::err(usage_error("--section requires a section name"));
            }
            parsed.section = std::string{section_name};
            continue;
        }
        if (is_flag(argument)) {
            return Result<Arguments>::err(usage_error("unknown option: " + std::string{argument}));
        }

        positional.emplace_back(argument);
    }

    if (positional.empty()) {
        parsed.action = Action::ShowHelp;
        return Result<Arguments>::ok(std::move(parsed));
    }
    if (positional.size() > 2U) {
        return Result<Arguments>::err(usage_error("too many positional arguments"));
    }

    parsed.file = std::filesystem::path{positional[0]};
    if (positional.size() == 2U) {
        parsed.symbol = positional[1];
    }

    if (parsed.section.has_value() && parsed.symbol.has_value()) {
        return Result<Arguments>::err(usage_error("use either a symbol or --section, not both"));
    }
    if (parsed.json && !parsed.symbol.has_value() && !parsed.section.has_value()) {
        return Result<Arguments>::err(usage_error("--json requires a symbol or --section"));
    }

    if (parsed.section.has_value()) {
        parsed.action = Action::DisassembleSection;
    } else if (parsed.symbol.has_value()) {
        parsed.action = Action::DisassembleSymbol;
    } else {
        parsed.action = Action::ListFunctions;
    }

    return Result<Arguments>::ok(std::move(parsed));
}

int run(const Arguments& args, std::ostream& out, std::ostream& err)
{
    const format::Options output_options = format_options(args);

    if (args.action == Action::ShowHelp) {
        return write_rendered(format::render_help(), out, err, output_options);
    }
    if (args.action == Action::ShowVersion) {
        return write_rendered(format::render_banner(), out, err, output_options);
    }
    if (!args.file.has_value()) {
        write_error(err, usage_error("missing file"), output_options);
        return exit_usage;
    }

    Result<elf::File> parsed_file = elf::parse_file(args.file.value());
    if (!parsed_file) {
        write_error(err, parsed_file.error(), output_options);
        return exit_file_error;
    }

    Result<resolver::Index> index = resolver::build_index(parsed_file.value());
    if (!index) {
        write_error(err, index.error(), output_options);
        return exit_disasm_error;
    }

    if (args.action == Action::ListFunctions) {
        return write_rendered(
            format::render_function_list(parsed_file.value(), index.value(), output_options),
            out,
            err,
            output_options);
    }

    const disasm::Options decode_options = disasm_options_for(parsed_file.value());
    std::vector<disasm::Instruction> instructions;

    if (args.action == Action::DisassembleSymbol) {
        if (!args.symbol.has_value()) {
            write_error(err, internal_error("missing symbol argument"), output_options);
            return exit_usage;
        }
        const std::optional<elf::Symbol> symbol = elf::find_symbol(parsed_file.value(), args.symbol.value());
        if (!symbol.has_value()) {
            write_missing_symbol_error(err, args.symbol.value(), parsed_file.value());
            return exit_disasm_error;
        }

        Result<std::vector<disasm::Instruction>> decoded =
            disasm::disassemble_function(parsed_file.value(), symbol.value(), decode_options);
        if (!decoded) {
            write_error(err, decoded.error(), output_options);
            return disassembly_exit_for(decoded.error().code);
        }
        instructions = std::move(decoded).value();
    } else if (args.action == Action::DisassembleSection) {
        if (!args.section.has_value()) {
            write_error(err, internal_error("missing section argument"), output_options);
            return exit_usage;
        }
        const std::optional<elf::Section> section = elf::find_section(parsed_file.value(), args.section.value());
        if (!section.has_value()) {
            write_error(err, Error{ErrorCode::NotFound, "section not found: " + args.section.value(), 0, false}, output_options);
            return exit_file_error;
        }

        Result<std::vector<disasm::Instruction>> decoded =
            disasm::disassemble_section(parsed_file.value(), section.value(), decode_options);
        if (!decoded) {
            write_error(err, decoded.error(), output_options);
            return disassembly_exit_for(decoded.error().code);
        }
        instructions = std::move(decoded).value();
    } else {
        write_error(err, internal_error("unsupported action"), output_options);
        return exit_usage;
    }

    std::vector<resolver::AnnotatedInstruction> annotated = resolver::annotate(index.value(), instructions);
    return write_rendered(render_annotated(annotated, args, output_options), out, err, output_options);
}

int main_entry(int argc, char** argv, std::ostream& out, std::ostream& err)
{
    Result<Arguments> parsed = parse_args(argc, argv);
    if (!parsed) {
        Arguments defaults;
        const format::Options output_options = format_options(defaults);
        write_error(err, parsed.error(), output_options);
        return exit_usage;
    }

    return run(parsed.value(), out, err);
}

} // namespace roe::cli
