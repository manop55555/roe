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

#include <cstdlib>
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
    options.show_bytes = config.show_bytes || parsed.show_bytes;
    options.source = config.source || parsed.source;
    options.pager = config.pager && !parsed.no_pager;
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
        } else if (is_flag(argument)) {
            return Result<Arguments>::err(usage_error("unknown option: " + std::string(argument)));
        } else {
            positional.emplace_back(argument);
        }
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
    const bool has_filter =
        parsed.grep_pattern.has_value() || parsed.calls_symbol.has_value() || parsed.contains_string.has_value();
    if (has_filter && (parsed.symbol.has_value() || parsed.section.has_value())) {
        return Result<Arguments>::err(usage_error("--grep/--calls/--contains filter the function list; omit a symbol or --section"));
    }

    if (parsed.xref_symbol.has_value()) {
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

    switch (args.action) {
    case Action::ListFunctions:
        return run_list(file, *object, index.value(), args, opts, out, err);
    case Action::DisassembleSymbol:
        return run_disassemble_symbol(file, *object, index.value(), args, opts, out, err);
    case Action::DisassembleSection:
        return run_disassemble_section(file, *object, index.value(), args, opts, out, err);
    case Action::DisassembleAll:
        return run_disassemble_all(file, *object, index.value(), args, opts, out, err);
    case Action::ShowXrefs:
        return run_xrefs(file, *object, index.value(), args, opts, out, err);
    case Action::ShowStats:
        return run_stats(file, *object, index.value(), args, opts, out, err);
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
