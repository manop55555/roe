// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The roe Authors

#include "roe/cli.hpp"

#include "roe/binary.hpp"
#include "roe/debug.hpp"
#include "roe/disasm.hpp"
#include "roe/features.hpp"
#include "roe/format.hpp"
#include "roe/resolver.hpp"
#include "roe/version.hpp"
#include "roe/watcher.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <iostream>
#include <iterator>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace roe::cli {
namespace {

Error usage_error(std::string message)
{
    return Error{ErrorCode::Usage, std::move(message), 0, false};
}

bool is_flag(std::string_view argument) noexcept
{
    return argument.size() > 1 && argument[0] == '-';
}

bool no_color_env_set() noexcept
{
    return std::getenv("NO_COLOR") != nullptr;
}

format::Options format_options(const Arguments& parsed)
{
    const features::Config config = features::load_config();
    format::Options options = format::default_options();
    options.mode = parsed.json ? format::Mode::Json : format::Mode::Text;
    options.no_color_env = no_color_env_set();
    options.color = config.color && !parsed.no_color && !options.no_color_env;
    options.preserve_addresses = true;
    options.show_bytes = config.show_bytes || parsed.show_bytes || parsed.verbose >= 1;
    options.source = config.source || parsed.source;
    options.pager = config.pager && !parsed.no_pager;
    options.quiet = parsed.quiet;
    options.verbose = parsed.verbose;
    if (parsed.quiet) {
        options.color = false; // quiet output is meant for pipelines
    }
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
    stream << program_name << ": error: " << error.message << '\n';
}

void write_missing_symbol_error(std::ostream& stream, std::string_view symbol, std::string_view source, bool stripped)
{
    stream << "error: symbol '" << symbol << "' not found in " << source << "\n";
    if (stripped) {
        stream << "\n";
        stream << "hint: the binary is stripped (.symtab is absent). try:\n";
        stream << "  - using an unstripped binary, or\n";
        stream << "  - listing available dynamic symbols: roe " << source << "\n";
    }
}

int exit_for(ErrorCode code) noexcept
{
    switch (code) {
    case ErrorCode::Usage:
        return exit_usage;
    case ErrorCode::FileIo:
    case ErrorCode::MalformedInput:
    case ErrorCode::UnsupportedFormat:
        return exit_file_error;
    default:
        return exit_disasm_error;
    }
}

int write_rendered(Result<std::string> rendered, std::ostream& out, std::ostream& err, const format::Options& options)
{
    if (!rendered) {
        const int code = exit_for(rendered.error().code);
        write_error(err, rendered.error(), options);
        return code;
    }
    write_line(out, rendered.value());
    return exit_ok;
}

std::optional<binary::Architecture> arch_from_name(std::string_view name) noexcept
{
    static const std::pair<std::string_view, binary::Architecture> table[] = {
        {"x86", binary::Architecture::X86},          {"i386", binary::Architecture::X86},
        {"x86_64", binary::Architecture::X86_64},    {"x86-64", binary::Architecture::X86_64},
        {"amd64", binary::Architecture::X86_64},     {"arm", binary::Architecture::Arm},
        {"armv7", binary::Architecture::Arm},        {"thumb", binary::Architecture::ArmThumb},
        {"arm-thumb", binary::Architecture::ArmThumb}, {"aarch64", binary::Architecture::AArch64},
        {"arm64", binary::Architecture::AArch64},    {"riscv32", binary::Architecture::RiscV32},
        {"riscv64", binary::Architecture::RiscV64},  {"mips", binary::Architecture::Mips32},
        {"mipsel", binary::Architecture::Mips32el},  {"mips64", binary::Architecture::Mips64},
        {"mips64el", binary::Architecture::Mips64el}, {"ppc", binary::Architecture::PowerPc32},
        {"powerpc", binary::Architecture::PowerPc32}, {"ppc64", binary::Architecture::PowerPc64},
        {"ppc64le", binary::Architecture::PowerPc64le},
    };
    for (const auto& [key, value] : table) {
        if (key == name) {
            return value;
        }
    }
    return std::nullopt;
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

// Find a function target by raw or demangled name, returning its address and size.
struct TargetSymbol {
    std::uint64_t address{0};
    std::uint64_t size{0};
};

std::optional<TargetSymbol> find_target(const resolver::Index& index, const binary::FileView& view, std::string_view name)
{
    for (const resolver::ResolvedSymbol& symbol : index.symbols) {
        if (symbol.name == name || symbol.raw_name == name) {
            return TargetSymbol{symbol.address, symbol.size};
        }
    }
    if (const std::optional<binary::Symbol> symbol = binary::find_symbol(view, 0, name)) {
        return TargetSymbol{symbol->address, symbol->size};
    }
    return std::nullopt;
}

// Parse a non-negative integer in hex (0x...) or decimal; nullopt on malformed input.
std::optional<std::uint64_t> parse_number(std::string_view text) noexcept
{
    if (text.empty()) {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    std::size_t index = 0;
    std::uint64_t base = 10;
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        base = 16;
        index = 2;
    }
    bool any = false;
    for (; index < text.size(); ++index) {
        const char c = text[index];
        std::uint64_t digit = 0;
        if (c >= '0' && c <= '9') {
            digit = static_cast<std::uint64_t>(c - '0');
        } else if (base == 16 && c >= 'a' && c <= 'f') {
            digit = 10U + static_cast<std::uint64_t>(c - 'a');
        } else if (base == 16 && c >= 'A' && c <= 'F') {
            digit = 10U + static_cast<std::uint64_t>(c - 'A');
        } else {
            return std::nullopt;
        }
        value = value * base + digit;
        any = true;
    }
    return any ? std::optional<std::uint64_t>(value) : std::nullopt;
}

} // namespace

Result<Arguments> parse_args(int argc, char** argv)
{
    if (argc < 0 || (argc > 0 && argv == nullptr)) {
        return Result<Arguments>::err(usage_error("invalid argv"));
    }

    Arguments parsed;
    std::vector<std::string> positional;

    const auto value_for = [&](int& index, std::string_view flag) -> Result<std::string> {
        if (index + 1 >= argc || argv[index + 1] == nullptr || is_flag(argv[index + 1])) {
            return Result<std::string>::err(usage_error(std::string(flag) + " requires a value"));
        }
        ++index;
        return Result<std::string>::ok(std::string(argv[index]));
    };

    for (int index = 1; index < argc; ++index) {
        if (argv[index] == nullptr) {
            return Result<Arguments>::err(usage_error("invalid null argument"));
        }
        const std::string_view argument{argv[index]};

        if (argument == "--help" || argument == "-h") {
            parsed.action = Action::ShowHelp;
            if (index + 1 < argc && argv[index + 1] != nullptr && !is_flag(argv[index + 1])) {
                parsed.help_topic = std::string(argv[index + 1]);
            }
            return Result<Arguments>::ok(std::move(parsed));
        }
        if (argument == "--version" || argument == "-V") {
            parsed.action = Action::ShowVersion;
            return Result<Arguments>::ok(std::move(parsed));
        }
        if (argument == "--completions") {
            Result<std::string> shell = value_for(index, "--completions");
            if (!shell) {
                return Result<Arguments>::err(std::move(shell).error());
            }
            parsed.completions_shell = std::move(shell).value();
            parsed.action = Action::ShowCompletions;
            return Result<Arguments>::ok(std::move(parsed));
        }
        if (argument == "--no-color") {
            parsed.no_color = true;
        } else if (argument == "--no-pager") {
            parsed.no_pager = true;
        } else if (argument == "--json") {
            parsed.json = true;
        } else if (argument == "--show-bytes") {
            parsed.show_bytes = true;
        } else if (argument == "--source") {
            parsed.source = true;
        } else if (argument == "--watch") {
            parsed.watch = true;
        } else if (argument == "--stats") {
            parsed.stats = true;
        } else if (argument == "--all" || argument == "-D") {
            parsed.all_sections = true;
        } else if (argument == "--section") {
            Result<std::string> value = value_for(index, "--section");
            if (!value) {
                return Result<Arguments>::err(std::move(value).error());
            }
            parsed.section = std::move(value).value();
        } else if (argument.rfind("--section=", 0) == 0) {
            const std::string_view name = argument.substr(std::string_view("--section=").size());
            if (name.empty()) {
                return Result<Arguments>::err(usage_error("--section requires a section name"));
            }
            parsed.section = std::string(name);
        } else if (argument == "--grep") {
            Result<std::string> value = value_for(index, "--grep");
            if (!value) {
                return Result<Arguments>::err(std::move(value).error());
            }
            parsed.grep_pattern = std::move(value).value();
        } else if (argument == "--calls") {
            Result<std::string> value = value_for(index, "--calls");
            if (!value) {
                return Result<Arguments>::err(std::move(value).error());
            }
            parsed.calls_symbol = std::move(value).value();
        } else if (argument == "--contains") {
            Result<std::string> value = value_for(index, "--contains");
            if (!value) {
                return Result<Arguments>::err(std::move(value).error());
            }
            parsed.contains_string = std::move(value).value();
        } else if (argument == "--xref") {
            Result<std::string> value = value_for(index, "--xref");
            if (!value) {
                return Result<Arguments>::err(std::move(value).error());
            }
            parsed.xref_symbol = std::move(value).value();
        } else if (argument == "--arch") {
            Result<std::string> value = value_for(index, "--arch");
            if (!value) {
                return Result<Arguments>::err(std::move(value).error());
            }
            if (!arch_from_name(value.value()).has_value()) {
                return Result<Arguments>::err(usage_error("unknown architecture: " + value.value()));
            }
            parsed.arch = std::move(value).value();
        } else if (argument == "--headers") {
            parsed.headers = true;
        } else if (argument == "--sections") {
            parsed.sections = true;
        } else if (argument == "--segments") {
            parsed.segments = true;
        } else if (argument == "--imports") {
            parsed.imports = true;
        } else if (argument == "--exports") {
            parsed.exports = true;
        } else if (argument == "--strings") {
            parsed.strings = true;
        } else if (argument == "--raw-bytes") {
            parsed.raw_bytes = true;
        } else if (argument == "--hex-input") {
            parsed.hex_input = true;
        } else if (argument == "--quiet" || argument == "-q") {
            parsed.quiet = true;
        } else if (argument == "--verbose" || argument == "-v") {
            ++parsed.verbose;
        } else if (argument == "--hex") {
            parsed.hex = true;
            if (index + 1 < argc && argv[index + 1] != nullptr) {
                const std::string_view next{argv[index + 1]};
                if (!next.empty() && (next[0] == '.' || next[0] == '_')) {
                    parsed.hex_section = std::string(next);
                    ++index;
                }
            }
        } else if (argument == "--addr") {
            Result<std::string> value = value_for(index, "--addr");
            if (!value) {
                return Result<Arguments>::err(std::move(value).error());
            }
            const std::optional<std::uint64_t> n = parse_number(value.value());
            if (!n.has_value()) {
                return Result<Arguments>::err(usage_error("--addr requires a hex or decimal address"));
            }
            parsed.addr = n;
        } else if (argument == "--range") {
            Result<std::string> value = value_for(index, "--range");
            if (!value) {
                return Result<Arguments>::err(std::move(value).error());
            }
            const std::string text = value.value();
            const auto dash = text.find('-', text.rfind("0x") == 0 ? 2U : 0U);
            if (dash == std::string::npos) {
                return Result<Arguments>::err(usage_error("--range must be <start>-<end>"));
            }
            const std::optional<std::uint64_t> start = parse_number(text.substr(0, dash));
            const std::optional<std::uint64_t> end = parse_number(text.substr(dash + 1));
            if (!start.has_value() || !end.has_value() || end.value() < start.value()) {
                return Result<Arguments>::err(usage_error("--range must be <start>-<end> with end >= start"));
            }
            parsed.range_start = start;
            parsed.range_end = end;
        } else if (argument == "--bytes") {
            Result<std::string> value = value_for(index, "--bytes");
            if (!value) {
                return Result<Arguments>::err(std::move(value).error());
            }
            parsed.bytes_count = parse_number(value.value());
            if (!parsed.bytes_count.has_value()) {
                return Result<Arguments>::err(usage_error("--bytes requires a count"));
            }
        } else if (argument == "--base") {
            Result<std::string> value = value_for(index, "--base");
            if (!value) {
                return Result<Arguments>::err(std::move(value).error());
            }
            parsed.base = parse_number(value.value());
            if (!parsed.base.has_value()) {
                return Result<Arguments>::err(usage_error("--base requires a hex or decimal address"));
            }
        } else if (argument == "--min-len") {
            Result<std::string> value = value_for(index, "--min-len");
            if (!value) {
                return Result<Arguments>::err(std::move(value).error());
            }
            parsed.min_len = parse_number(value.value());
            if (!parsed.min_len.has_value()) {
                return Result<Arguments>::err(usage_error("--min-len requires a number"));
            }
        } else if (argument == "--diff") {
            Result<std::string> value = value_for(index, "--diff");
            if (!value) {
                return Result<Arguments>::err(std::move(value).error());
            }
            parsed.diff_other = std::filesystem::path{std::move(value).value()};
        } else if (argument == "--find") {
            Result<std::string> value = value_for(index, "--find");
            if (!value) {
                return Result<Arguments>::err(std::move(value).error());
            }
            parsed.find_pattern = std::move(value).value();
        } else if (is_flag(argument)) {
            return Result<Arguments>::err(usage_error("unknown option: " + std::string(argument)));
        } else {
            positional.emplace_back(argument);
        }
    }

    // --raw-bytes reads stdin and needs no input file.
    if (parsed.raw_bytes) {
        if (!parsed.arch.has_value()) {
            return Result<Arguments>::err(usage_error("--raw-bytes requires --arch <name>"));
        }
        if (!positional.empty()) {
            return Result<Arguments>::err(usage_error("--raw-bytes reads bytes from stdin; do not also pass a file"));
        }
        parsed.action = Action::RawBytes;
        return Result<Arguments>::ok(std::move(parsed));
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
    if (parsed.addr.has_value() && parsed.range_start.has_value()) {
        return Result<Arguments>::err(usage_error("use either --addr or --range, not both"));
    }
    const bool has_filter =
        parsed.grep_pattern.has_value() || parsed.calls_symbol.has_value() || parsed.contains_string.has_value();
    if (has_filter && (parsed.symbol.has_value() || parsed.section.has_value())) {
        return Result<Arguments>::err(usage_error("--grep/--calls/--contains filter the function list; omit a symbol or --section"));
    }

    if (parsed.diff_other.has_value()) {
        parsed.action = Action::ShowDiff;
    } else if (parsed.headers) {
        parsed.action = Action::ShowHeaders;
    } else if (parsed.sections) {
        parsed.action = Action::ShowSections;
    } else if (parsed.segments) {
        parsed.action = Action::ShowSegments;
    } else if (parsed.imports) {
        parsed.action = Action::ShowImports;
    } else if (parsed.exports) {
        parsed.action = Action::ShowExports;
    } else if (parsed.strings) {
        parsed.action = Action::ShowStrings;
    } else if (parsed.find_pattern.has_value()) {
        parsed.action = Action::ShowFind;
    } else if (parsed.hex) {
        parsed.action = Action::ShowHex;
    } else if (parsed.addr.has_value()) {
        parsed.action = Action::DisassembleAddr;
    } else if (parsed.range_start.has_value()) {
        parsed.action = Action::DisassembleRange;
    } else if (parsed.xref_symbol.has_value()) {
        parsed.action = Action::ShowXrefs;
    } else if (parsed.stats) {
        parsed.action = Action::ShowStats;
    } else if (parsed.all_sections) {
        parsed.action = Action::DisassembleAll;
    } else if (parsed.section.has_value()) {
        parsed.action = Action::DisassembleSection;
    } else if (parsed.symbol.has_value()) {
        parsed.action = Action::DisassembleSymbol;
    } else {
        parsed.action = Action::ListFunctions;
    }

    return Result<Arguments>::ok(std::move(parsed));
}

namespace {

disasm::Options decode_options_for(const binary::Object& object, const Arguments& args)
{
    binary::Architecture architecture = object.architecture;
    if (args.arch.has_value()) {
        if (const std::optional<binary::Architecture> override = arch_from_name(args.arch.value())) {
            architecture = *override;
        }
    }
    const features::Config config = features::load_config();
    const disasm::Syntax syntax = config.syntax == "att" ? disasm::Syntax::Att : disasm::Syntax::Intel;
    Result<disasm::Options> options = disasm::options_for(architecture, syntax);
    if (options) {
        return options.value();
    }
    disasm::Options fallback;
    fallback.architecture = disasm::Architecture::X86_64;
    return fallback;
}

// When --source is requested, load DWARF line info and attach source lines to the
// annotated instructions. Emits a single info line to err when debug info is absent.
void attach_source(
    const binary::BinaryFile& file,
    const Arguments& args,
    std::vector<resolver::AnnotatedInstruction>& annotated,
    std::ostream& err)
{
    if (!args.source) {
        return;
    }
    Result<debug::SourceMap> map = debug::load_source_map(file, 0);
    if (!map) {
        return;
    }
    if (!map.value().fallback_message.empty()) {
        err << "info: " << map.value().fallback_message << "\n";
        return;
    }
    for (resolver::AnnotatedInstruction& entry : annotated) {
        const std::optional<debug::SourceLocation> location =
            debug::source_at(map.value(), entry.instruction.address);
        if (location.has_value()) {
            entry.source_text = location->text;
            entry.source_line = location->line;
            entry.source_path = location->path;
        }
    }
}

int run_disassemble_symbol(
    const binary::BinaryFile& file,
    const binary::Object& object,
    const resolver::Index& index,
    const Arguments& args,
    const format::Options& opts,
    std::ostream& out,
    std::ostream& err)
{
    const std::optional<TargetSymbol> target = find_target(index, file.view(), args.symbol.value());
    if (!target.has_value()) {
        write_missing_symbol_error(err, args.symbol.value(), file.view().source_name, object.stripped);
        return exit_disasm_error;
    }

    binary::Symbol symbol;
    symbol.address = target->address;
    symbol.size = target->size;
    const disasm::Options decode = decode_options_for(object, args);
    Result<std::vector<disasm::Instruction>> decoded = disasm::disassemble_function(file, object, symbol, decode);
    if (!decoded) {
        write_error(err, decoded.error(), opts);
        return exit_for(decoded.error().code);
    }

    std::vector<resolver::AnnotatedInstruction> annotated = resolver::annotate(index, decoded.value());
    annotated = features::annotate_string_references(object, annotated);
    attach_source(file, args, annotated, err);
    return write_rendered(render_annotated(annotated, args, opts), out, err, opts);
}

int run_disassemble_section(
    const binary::BinaryFile& file,
    const binary::Object& object,
    const resolver::Index& index,
    const Arguments& args,
    const format::Options& opts,
    std::ostream& out,
    std::ostream& err)
{
    const std::optional<binary::Section> section = binary::find_section(file.view(), 0, args.section.value());
    if (!section.has_value()) {
        write_error(err, Error{ErrorCode::NotFound, "section not found: " + args.section.value(), 0, false}, opts);
        return exit_file_error;
    }

    Result<binary::SectionBytes> bytes = file.section_bytes(*section);
    if (!bytes) {
        write_error(err, bytes.error(), opts);
        return exit_for(bytes.error().code);
    }

    const disasm::Options decode = decode_options_for(object, args);
    Result<std::vector<disasm::Instruction>> decoded = disasm::disassemble_section(bytes.value(), decode);
    if (!decoded) {
        write_error(err, decoded.error(), opts);
        return exit_for(decoded.error().code);
    }

    std::vector<resolver::AnnotatedInstruction> annotated = resolver::annotate(index, decoded.value());
    annotated = features::annotate_string_references(object, annotated);
    attach_source(file, args, annotated, err);
    return write_rendered(render_annotated(annotated, args, opts), out, err, opts);
}

int run_disassemble_all(
    const binary::BinaryFile& file,
    const binary::Object& object,
    const resolver::Index& index,
    const Arguments& args,
    const format::Options& opts,
    std::ostream& out,
    std::ostream& err)
{
    const disasm::Options decode = decode_options_for(object, args);
    std::string combined;
    bool any = false;
    for (const binary::Section& section : object.sections) {
        if (!section.executable || section.size == 0U) {
            continue;
        }
        Result<binary::SectionBytes> bytes = file.section_bytes(section);
        if (!bytes) {
            continue;
        }
        Result<std::vector<disasm::Instruction>> decoded = disasm::disassemble_section(bytes.value(), decode);
        if (!decoded) {
            continue;
        }
        std::vector<resolver::AnnotatedInstruction> annotated = resolver::annotate(index, decoded.value());
        annotated = features::annotate_string_references(object, annotated);
        Result<std::string> rendered = render_annotated(annotated, args, opts);
        if (!rendered) {
            continue;
        }
        if (any) {
            combined += "\n";
        }
        combined += "Section " + section.name + "\n";
        combined += rendered.value();
        any = true;
    }
    if (!any) {
        write_error(err, Error{ErrorCode::NotFound, "no executable sections to disassemble", 0, false}, opts);
        return exit_file_error;
    }
    write_line(out, combined);
    return exit_ok;
}

std::vector<features::FunctionBody> build_function_bodies(
    const binary::BinaryFile& file,
    const binary::Object& object,
    const resolver::Index& index,
    const disasm::Options& decode)
{
    std::vector<features::FunctionBody> bodies;
    for (const binary::Symbol& symbol : object.symbols) {
        if (symbol.type != binary::SymbolType::Function || !symbol.defined || symbol.name.empty()) {
            continue;
        }
        if (symbol.name.rfind(".L", 0) == 0 || symbol.name.front() == '$') {
            continue;
        }
        Result<std::vector<disasm::Instruction>> decoded = disasm::disassemble_function(file, object, symbol, decode);
        if (!decoded) {
            continue;
        }
        std::vector<resolver::AnnotatedInstruction> annotated = resolver::annotate(index, decoded.value());
        annotated = features::annotate_string_references(object, annotated);
        bodies.push_back(features::FunctionBody{symbol, std::move(annotated)});
    }
    return bodies;
}

int run_list(
    const binary::BinaryFile& file,
    const binary::Object& object,
    const resolver::Index& index,
    const Arguments& args,
    const format::Options& opts,
    std::ostream& out,
    std::ostream& err)
{
    const std::string source = file.view().source_name;
    if (args.grep_pattern.has_value()) {
        const std::vector<binary::Symbol> functions = binary::function_symbols(file.view(), 0);
        Result<std::vector<binary::Symbol>> filtered = features::filter_functions(functions, args.grep_pattern.value());
        if (!filtered) {
            write_error(err, filtered.error(), opts);
            return exit_for(filtered.error().code);
        }
        return write_rendered(
            format::render_function_table("Functions matching /" + args.grep_pattern.value() + "/ in " + source,
                filtered.value(), index, opts),
            out, err, opts);
    }
    if (args.calls_symbol.has_value()) {
        const std::vector<features::FunctionBody> bodies =
            build_function_bodies(file, object, index, decode_options_for(object, args));
        const std::vector<binary::Symbol> matched = features::functions_calling(bodies, args.calls_symbol.value());
        return write_rendered(
            format::render_function_table("Functions calling " + args.calls_symbol.value() + " in " + source,
                matched, index, opts),
            out, err, opts);
    }
    if (args.contains_string.has_value()) {
        const std::vector<features::FunctionBody> bodies =
            build_function_bodies(file, object, index, decode_options_for(object, args));
        const std::vector<binary::Symbol> matched =
            features::functions_containing_string(bodies, args.contains_string.value());
        return write_rendered(
            format::render_function_table("Functions referencing \"" + args.contains_string.value() + "\" in " + source,
                matched, index, opts),
            out, err, opts);
    }
    return write_rendered(format::render_function_list(file.view(), index, opts), out, err, opts);
}

int run_xrefs(
    const binary::BinaryFile& file,
    const binary::Object& object,
    const resolver::Index& index,
    const Arguments& args,
    const format::Options& opts,
    std::ostream& out,
    std::ostream& err)
{
    const std::vector<features::FunctionBody> bodies =
        build_function_bodies(file, object, index, decode_options_for(object, args));
    const std::vector<features::Xref> xrefs = features::find_xrefs(bodies, args.xref_symbol.value());
    return write_rendered(format::render_xrefs(xrefs, opts), out, err, opts);
}

int run_stats(
    const binary::BinaryFile& file,
    const binary::Object& object,
    const resolver::Index& index,
    const Arguments& args,
    const format::Options& opts,
    std::ostream& out,
    std::ostream& err)
{
    std::vector<features::FunctionBody> bodies =
        build_function_bodies(file, object, index, decode_options_for(object, args));
    if (args.symbol.has_value()) {
        std::vector<features::FunctionBody> selected;
        for (features::FunctionBody& body : bodies) {
            if (body.symbol.name == args.symbol.value() || body.symbol.raw_name == args.symbol.value()) {
                selected.push_back(std::move(body));
            }
        }
        bodies.swap(selected);
    }
    const std::vector<features::FunctionStats> stats = features::compute_stats(bodies);
    return write_rendered(format::render_stats(stats, opts), out, err, opts);
}

std::string to_lower(std::string text)
{
    for (char& c : text) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return text;
}

std::optional<binary::Section> section_containing(const binary::Object& object, std::uint64_t address)
{
    for (const binary::Section& section : object.sections) {
        if (section.address <= address && address < section.address + section.size) {
            return section;
        }
    }
    return std::nullopt;
}

std::vector<std::uint8_t> read_stdin_bytes()
{
    std::vector<std::uint8_t> data;
    std::istreambuf_iterator<char> it(std::cin);
    const std::istreambuf_iterator<char> end;
    for (; it != end; ++it) {
        data.push_back(static_cast<std::uint8_t>(*it));
    }
    return data;
}

bool looks_like_hex_text(const std::vector<std::uint8_t>& bytes)
{
    bool any = false;
    for (const std::uint8_t b : bytes) {
        if (std::isxdigit(b) != 0) {
            any = true;
        } else if (b != ' ' && b != '\t' && b != '\n' && b != '\r') {
            return false;
        }
    }
    return any;
}

std::vector<std::uint8_t> parse_hex_bytes(const std::vector<std::uint8_t>& bytes)
{
    std::string digits;
    for (const std::uint8_t b : bytes) {
        if (std::isxdigit(b) != 0) {
            digits.push_back(static_cast<char>(b));
        }
    }
    const auto value = [](char c) -> int {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        return c - 'A' + 10;
    };
    std::vector<std::uint8_t> out;
    for (std::size_t i = 0; i + 1 < digits.size(); i += 2) {
        out.push_back(static_cast<std::uint8_t>((value(digits[i]) * 16) + value(digits[i + 1])));
    }
    return out;
}

int run_raw_bytes(const Arguments& args, const format::Options& opts, std::ostream& out, std::ostream& err)
{
    const std::optional<binary::Architecture> arch = arch_from_name(args.arch.value_or(""));
    if (!arch.has_value()) {
        write_error(err, usage_error("--raw-bytes requires a known --arch"), opts);
        return exit_usage;
    }
    Result<disasm::Options> decode = disasm::options_for(*arch);
    if (!decode) {
        write_error(err, decode.error(), opts);
        return exit_disasm_error;
    }
    const std::vector<std::uint8_t> data = read_stdin_bytes();
    std::vector<std::uint8_t> code = (args.hex_input || looks_like_hex_text(data)) ? parse_hex_bytes(data) : data;
    if (code.empty()) {
        write_error(err, Error{ErrorCode::Usage, "no bytes received on stdin", 0, false}, opts);
        return exit_usage;
    }
    const std::uint64_t base = args.base.value_or(0);
    disasm::CodeBuffer buffer{base, code.begin(), code.end()};
    Result<std::vector<disasm::Instruction>> decoded = disasm::disassemble_bytes(buffer, decode.value());
    if (!decoded) {
        write_error(err, decoded.error(), opts);
        return exit_for(decoded.error().code);
    }
    const resolver::Index empty_index;
    std::vector<resolver::AnnotatedInstruction> annotated = resolver::annotate(empty_index, decoded.value());
    return write_rendered(render_annotated(annotated, args, opts), out, err, opts);
}

int run_disassemble_addr(
    const binary::BinaryFile& file,
    const binary::Object& object,
    const resolver::Index& index,
    const Arguments& args,
    const format::Options& opts,
    std::ostream& out,
    std::ostream& err)
{
    const bool is_range = args.action == Action::DisassembleRange;
    const std::uint64_t start = is_range ? args.range_start.value() : args.addr.value();
    const std::optional<binary::Section> section = section_containing(object, start);
    if (!section.has_value() || !section->executable) {
        write_error(err, Error{ErrorCode::NotFound, "address is not in an executable section", start, true}, opts);
        return exit_file_error;
    }
    Result<binary::SectionBytes> bytes = file.section_bytes(*section);
    if (!bytes) {
        write_error(err, bytes.error(), opts);
        return exit_for(bytes.error().code);
    }
    const std::vector<std::uint8_t>& data = bytes.value().bytes;
    const std::uint64_t begin_off = start - section->address;
    if (begin_off >= data.size()) {
        write_error(err, Error{ErrorCode::NotFound, "address has no backing bytes", start, true}, opts);
        return exit_file_error;
    }
    std::uint64_t end_off = 0;
    if (is_range) {
        const std::uint64_t inclusive_end = args.range_end.value();
        end_off = inclusive_end >= section->address ? (inclusive_end - section->address) + 1U : begin_off;
        end_off = std::min<std::uint64_t>(end_off, data.size());
    } else {
        // --addr: window to the section end, capped, then trimmed at the first terminal.
        end_off = std::min<std::uint64_t>(data.size(), begin_off + 65536U);
    }
    if (end_off <= begin_off) {
        end_off = std::min<std::uint64_t>(data.size(), begin_off + 1U);
    }
    std::vector<std::uint8_t> window(data.begin() + static_cast<std::ptrdiff_t>(begin_off),
        data.begin() + static_cast<std::ptrdiff_t>(end_off));
    disasm::CodeBuffer code{start, window.begin(), window.end()};
    Result<std::vector<disasm::Instruction>> decoded = disasm::disassemble_bytes(code, decode_options_for(object, args));
    if (!decoded) {
        write_error(err, decoded.error(), opts);
        return exit_for(decoded.error().code);
    }
    std::vector<disasm::Instruction> instructions = std::move(decoded).value();
    if (!is_range) {
        for (std::size_t i = 0; i < instructions.size(); ++i) {
            if (disasm::is_terminal(instructions[i].branch_kind)) {
                instructions.resize(i + 1);
                break;
            }
        }
    }
    std::vector<resolver::AnnotatedInstruction> annotated = resolver::annotate(index, instructions);
    annotated = features::annotate_string_references(object, annotated);
    return write_rendered(render_annotated(annotated, args, opts), out, err, opts);
}

int run_hex(
    const binary::BinaryFile& file,
    const binary::Object& object,
    const Arguments& args,
    const format::Options& opts,
    std::ostream& out,
    std::ostream& err)
{
    std::vector<std::uint8_t> bytes;
    std::uint64_t base = 0;
    if (args.hex_section.has_value()) {
        const std::optional<binary::Section> section = binary::find_section(file.view(), 0, args.hex_section.value());
        if (!section.has_value()) {
            write_error(err, Error{ErrorCode::NotFound, "section not found: " + args.hex_section.value(), 0, false}, opts);
            return exit_file_error;
        }
        Result<binary::SectionBytes> sb = file.section_bytes(*section);
        if (!sb) {
            write_error(err, sb.error(), opts);
            return exit_for(sb.error().code);
        }
        bytes = std::move(sb).value().bytes;
        base = section->address;
    } else if (args.addr.has_value() || args.range_start.has_value()) {
        const std::uint64_t start = args.addr.value_or(args.range_start.value_or(0));
        const std::optional<binary::Section> section = section_containing(object, start);
        if (!section.has_value()) {
            write_error(err, Error{ErrorCode::NotFound, "address is not in any section", start, true}, opts);
            return exit_file_error;
        }
        Result<binary::SectionBytes> sb = file.section_bytes(*section);
        if (!sb) {
            write_error(err, sb.error(), opts);
            return exit_for(sb.error().code);
        }
        const std::vector<std::uint8_t>& data = sb.value().bytes;
        const std::uint64_t off = start - section->address;
        std::uint64_t length = args.bytes_count.value_or(64U);
        if (args.range_start.has_value() && args.range_end.has_value()) {
            length = (args.range_end.value() - args.range_start.value()) + 1U;
        }
        if (off < data.size()) {
            const std::uint64_t available = data.size() - off;
            length = std::min<std::uint64_t>(length, available);
            bytes.assign(data.begin() + static_cast<std::ptrdiff_t>(off),
                data.begin() + static_cast<std::ptrdiff_t>(off + length));
        }
        base = start;
    } else {
        write_error(err, usage_error("--hex needs a section name, --addr, or --range"), opts);
        return exit_usage;
    }
    return write_rendered(format::render_hex(bytes, base, opts), out, err, opts);
}

int run_strings(
    const binary::BinaryFile& file,
    const binary::Object& object,
    const resolver::Index& index,
    const Arguments& args,
    const format::Options& opts,
    std::ostream& out,
    std::ostream& err)
{
    const std::vector<features::FunctionBody> bodies =
        build_function_bodies(file, object, index, decode_options_for(object, args));
    const std::uint64_t min_len = args.min_len.value_or(4U);
    const std::vector<features::StringRef> refs = features::find_string_references(object.strings, bodies, min_len);
    return write_rendered(format::render_strings(refs, opts), out, err, opts);
}

int run_find(
    const binary::BinaryFile& file,
    const binary::Object& object,
    const resolver::Index& index,
    const Arguments& args,
    const format::Options& opts,
    std::ostream& out,
    std::ostream& err)
{
    static_cast<void>(file);
    static_cast<void>(index);
    const std::string pattern = to_lower(args.find_pattern.value());
    std::vector<features::FindMatch> matches;
    for (const binary::Symbol& symbol : object.symbols) {
        const std::string display = symbol.name.empty() ? symbol.raw_name : symbol.name;
        if (display.empty()) {
            continue;
        }
        const std::string demangled = resolver::demangle(symbol.raw_name);
        if (to_lower(display).find(pattern) == std::string::npos &&
            to_lower(symbol.raw_name).find(pattern) == std::string::npos &&
            to_lower(demangled).find(pattern) == std::string::npos) {
            continue;
        }
        std::string source = "symtab";
        if (symbol.bind == binary::SymbolBind::Imported) {
            source = "import";
        } else if (symbol.bind == binary::SymbolBind::Exported) {
            source = "export";
        } else if (symbol.dynamic) {
            source = "dynsym";
        }
        matches.push_back(features::FindMatch{demangled != symbol.raw_name ? demangled : display, symbol.address, source});
    }
    std::sort(matches.begin(), matches.end(), [](const features::FindMatch& a, const features::FindMatch& b) {
        if (a.address != b.address) {
            return a.address < b.address;
        }
        return a.name < b.name;
    });
    return write_rendered(format::render_find(matches, args.find_pattern.value(), opts), out, err, opts);
}

int run_diff(
    const binary::BinaryFile& file,
    const binary::Object& object,
    const resolver::Index& index,
    const Arguments& args,
    const format::Options& opts,
    std::ostream& out,
    std::ostream& err)
{
    Result<std::unique_ptr<binary::BinaryFile>> other = binary::load_file(args.diff_other.value());
    if (!other) {
        write_error(err, other.error(), opts);
        return exit_for(other.error().code);
    }
    const std::optional<binary::Object> other_object = binary::primary_object(other.value()->view());
    if (!other_object.has_value()) {
        write_error(err, Error{ErrorCode::MalformedInput, "the --diff binary has no analyzable object", 0, false}, opts);
        return exit_file_error;
    }
    Result<resolver::Index> other_index = resolver::build_index(*other.value());
    if (!other_index) {
        write_error(err, other_index.error(), opts);
        return exit_disasm_error;
    }

    const std::vector<features::FunctionBody> new_bodies =
        build_function_bodies(file, object, index, decode_options_for(object, args));
    const std::vector<features::FunctionBody> old_bodies =
        build_function_bodies(*other.value(), *other_object, other_index.value(), decode_options_for(*other_object, args));

    if (args.symbol.has_value()) {
        const auto find_body = [](const std::vector<features::FunctionBody>& bodies, const std::string& name)
            -> const features::FunctionBody* {
            for (const features::FunctionBody& body : bodies) {
                if (body.symbol.name == name || body.symbol.raw_name == name) {
                    return &body;
                }
            }
            return nullptr;
        };
        const features::FunctionBody* new_fn = find_body(new_bodies, args.symbol.value());
        const features::FunctionBody* old_fn = find_body(old_bodies, args.symbol.value());
        if (new_fn == nullptr && old_fn == nullptr) {
            write_missing_symbol_error(err, args.symbol.value(), file.view().source_name, object.stripped);
            return exit_disasm_error;
        }
        const auto to_lines = [](const features::FunctionBody* fn) {
            std::vector<std::string> lines;
            if (fn != nullptr) {
                for (const resolver::AnnotatedInstruction& a : fn->instructions) {
                    lines.push_back(a.instruction.mnemonic + (a.instruction.operands.empty() ? "" : " " + a.instruction.operands));
                }
            }
            return lines;
        };
        const std::vector<std::string> old_lines = to_lines(old_fn);
        const std::vector<std::string> new_lines = to_lines(new_fn);
        std::ostringstream body;
        body << "diff of " << args.symbol.value() << " (" << args.diff_other.value().string() << " -> "
             << file.view().source_name << ")\n";
        // Longest-common-subsequence diff, bounded to keep memory sane.
        const std::size_t n = old_lines.size();
        const std::size_t m = new_lines.size();
        if (n > 4000 || m > 4000) {
            for (const std::string& l : old_lines) {
                body << "- " << l << "\n";
            }
            for (const std::string& l : new_lines) {
                body << "+ " << l << "\n";
            }
        } else {
            std::vector<std::vector<std::uint32_t>> dp(n + 1, std::vector<std::uint32_t>(m + 1, 0));
            for (std::size_t i = n; i-- > 0;) {
                for (std::size_t j = m; j-- > 0;) {
                    dp[i][j] = old_lines[i] == new_lines[j] ? dp[i + 1][j + 1] + 1
                                                            : std::max(dp[i + 1][j], dp[i][j + 1]);
                }
            }
            std::size_t i = 0;
            std::size_t j = 0;
            while (i < n && j < m) {
                if (old_lines[i] == new_lines[j]) {
                    body << "  " << old_lines[i];
                    ++i;
                    ++j;
                } else if (dp[i + 1][j] >= dp[i][j + 1]) {
                    body << "- " << old_lines[i];
                    ++i;
                } else {
                    body << "+ " << new_lines[j];
                    ++j;
                }
                body << "\n";
            }
            for (; i < n; ++i) {
                body << "- " << old_lines[i] << "\n";
            }
            for (; j < m; ++j) {
                body << "+ " << new_lines[j] << "\n";
            }
        }
        return write_rendered(Result<std::string>::ok(body.str()), out, err, opts);
    }

    const features::DiffResult result = features::diff_functions(old_bodies, new_bodies);
    return write_rendered(format::render_diff(result, opts), out, err, opts);
}

} // namespace

int execute(const Arguments& args, std::ostream& out, std::ostream& err)
{
    const format::Options opts = format_options(args);

    if (args.action == Action::ShowHelp) {
        if (args.help_topic.has_value()) {
            return write_rendered(format::render_help_topic(args.help_topic.value()), out, err, opts);
        }
        return write_rendered(format::render_help(), out, err, opts);
    }
    if (args.action == Action::ShowVersion) {
        return write_rendered(format::render_version(), out, err, opts);
    }
    if (args.action == Action::ShowCompletions) {
        return write_rendered(format::render_completions(args.completions_shell.value_or("bash")), out, err, opts);
    }
    if (args.action == Action::RawBytes) {
        return run_raw_bytes(args, opts, out, err);
    }

    if (!args.file.has_value()) {
        write_error(err, usage_error("missing file"), opts);
        return exit_usage;
    }

    Result<std::unique_ptr<binary::BinaryFile>> loaded = binary::load_file(args.file.value());
    if (!loaded) {
        write_error(err, loaded.error(), opts);
        return exit_for(loaded.error().code);
    }
    const binary::BinaryFile& file = *loaded.value();
    const std::optional<binary::Object> object = binary::primary_object(file.view());
    if (!object.has_value()) {
        write_error(err, Error{ErrorCode::MalformedInput, "binary contains no analyzable object", 0, false}, opts);
        return exit_file_error;
    }

    Result<resolver::Index> index = resolver::build_index(file);
    if (!index) {
        write_error(err, index.error(), opts);
        return exit_disasm_error;
    }

    if (args.verbose >= 2) {
        err << "debug: loaded " << binary::format_name(file.view().format) << " ("
            << binary::architecture_name(object->architecture) << "), " << object->sections.size()
            << " sections, " << object->symbols.size() << " symbols, " << object->relocations.size()
            << " relocations, " << index.value().symbols.size() << " resolved, " << object->strings.size()
            << " strings\n";
    }

    switch (args.action) {
    case Action::ListFunctions:
        return run_list(file, *object, index.value(), args, opts, out, err);
    case Action::DisassembleSymbol:
        return run_disassemble_symbol(file, *object, index.value(), args, opts, out, err);
    case Action::DisassembleSection:
        return run_disassemble_section(file, *object, index.value(), args, opts, out, err);
    case Action::DisassembleAll:
        return run_disassemble_all(file, *object, index.value(), args, opts, out, err);
    case Action::DisassembleAddr:
    case Action::DisassembleRange:
        return run_disassemble_addr(file, *object, index.value(), args, opts, out, err);
    case Action::ShowXrefs:
        return run_xrefs(file, *object, index.value(), args, opts, out, err);
    case Action::ShowStats:
        return run_stats(file, *object, index.value(), args, opts, out, err);
    case Action::ShowHeaders:
        return write_rendered(format::render_headers(file.view(), opts), out, err, opts);
    case Action::ShowSections:
        return write_rendered(format::render_sections(file.view(), opts), out, err, opts);
    case Action::ShowSegments:
        return write_rendered(format::render_segments(file.view(), opts), out, err, opts);
    case Action::ShowImports:
        return write_rendered(format::render_imports(file.view(), opts), out, err, opts);
    case Action::ShowExports:
        return write_rendered(format::render_exports(file.view(), opts), out, err, opts);
    case Action::ShowHex:
        return run_hex(file, *object, args, opts, out, err);
    case Action::ShowStrings:
        return run_strings(file, *object, index.value(), args, opts, out, err);
    case Action::ShowFind:
        return run_find(file, *object, index.value(), args, opts, out, err);
    case Action::ShowDiff:
        return run_diff(file, *object, index.value(), args, opts, out, err);
    case Action::RawBytes:
    case Action::Watch:
    case Action::ShowHelp:
    case Action::ShowVersion:
    case Action::ShowCompletions:
        break;
    }

    write_error(err, usage_error("unsupported action"), opts);
    return exit_usage;
}

int run(const Arguments& args, std::ostream& out, std::ostream& err)
{
    if (args.watch && args.file.has_value()) {
        Arguments once = args;
        once.watch = false;
        const format::Options opts = format_options(args);
        const watcher::Options watch_options;
        const Result<void> watched = watcher::watch_file(
            args.file.value(), watch_options, [&](const watcher::Event&) {
                if (opts.color) {
                    out << "\033[2J\033[H"; // clear the screen between runs
                }
                static_cast<void>(execute(once, out, err));
                out.flush();
            });
        if (!watched) {
            write_error(err, watched.error(), opts);
            return exit_usage;
        }
        return exit_ok;
    }
    return execute(args, out, err);
}

int main_entry(int argc, char** argv, std::ostream& out, std::ostream& err)
{
    Result<Arguments> parsed = parse_args(argc, argv);
    if (!parsed) {
        Arguments defaults;
        const format::Options opts = format_options(defaults);
        write_error(err, parsed.error(), opts);
        return exit_usage;
    }
    return run(parsed.value(), out, err);
}

} // namespace roe::cli
