// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The roe Authors
#include "roe/format.hpp"

#include "roe/version.hpp"

#include <algorithm>
#include <cstdlib>
#include <iomanip>
#include <map>
#include <optional>
#include <sstream>
#include <string_view>

namespace roe::format {
namespace {

constexpr std::string_view ansi_reset{"\033[0m"};
constexpr std::string_view ansi_bold{"\033[1m"};
constexpr std::string_view ansi_dim{"\033[2m"};
constexpr std::string_view ansi_green{"\033[32m"};
constexpr std::string_view ansi_red{"\033[31m"};
constexpr std::string_view ansi_yellow{"\033[33m"};
constexpr std::string_view ansi_cyan{"\033[36m"};

std::string colorize(std::string_view text, std::string_view code, const Options& options)
{
    if (!color_enabled(options)) {
        return std::string{text};
    }
    std::string rendered;
    rendered.reserve(code.size() + text.size() + ansi_reset.size());
    rendered.append(code);
    rendered.append(text);
    rendered.append(ansi_reset);
    return rendered;
}

std::string hex_address(std::uint64_t value)
{
    std::ostringstream out;
    out << "0x" << std::hex << std::nouppercase << value;
    return out.str();
}

std::string padded_hex_address(std::uint64_t value)
{
    std::ostringstream out;
    out << "0x" << std::hex << std::nouppercase << std::setfill('0') << std::setw(16) << value;
    return out.str();
}

std::string bytes_text(const std::vector<std::uint8_t>& bytes)
{
    std::ostringstream out;
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (index != 0) {
            out << ' ';
        }
        out << std::hex << std::nouppercase << std::setfill('0') << std::setw(2)
            << static_cast<unsigned int>(bytes[index]);
    }
    return out.str();
}

std::string instruction_text(const disasm::Instruction& instruction)
{
    if (instruction.operands.empty()) {
        return instruction.mnemonic;
    }
    return instruction.mnemonic + " " + instruction.operands;
}

// A token looks like a numeric immediate (0x1f, -8, #0x10) rather than a register.
bool looks_like_immediate(std::string_view token) noexcept
{
    std::size_t index = 0;
    if (index < token.size() && token[index] == '#') {
        ++index;
    }
    if (index < token.size() && token[index] == '-') {
        ++index;
    }
    bool has_digit = false;
    for (; index < token.size(); ++index) {
        const char character = token[index];
        if (character >= '0' && character <= '9') {
            has_digit = true;
        } else if (character == 'x' || character == 'X' || (character >= 'a' && character <= 'f') ||
                   (character >= 'A' && character <= 'F')) {
            continue;
        } else {
            return false;
        }
    }
    return has_digit;
}

std::string banner_text()
{
    std::ostringstream out;
    out << program_name << " v" << version_string << " \342\200\224 a disassembler fit for humans\n\n";
    out << "           (             )\n";
    out << "            `--(_   _)--'\n";
    out << "                 Y-Y\n";
    out << "                /@@ \\\n";
    out << "               /     \\\n";
    out << "               `--'.  \\             ,\n";
    out << "                   |   `.__________/)\n\n";
    out << "resolve relocations \302\267 preview branch targets \302\267 clean output\n";
    return out.str();
}

std::string display_name_for_function(const elf::Symbol& function, const resolver::Index& index)
{
    const auto exact = std::find_if(
        index.symbols.begin(),
        index.symbols.end(),
        [&function](const resolver::ResolvedSymbol& symbol) {
            return symbol.address == function.address && symbol.raw_name == function.name;
        });
    if (exact != index.symbols.end()) {
        return exact->name;
    }

    const auto same_address = std::find_if(
        index.symbols.begin(),
        index.symbols.end(),
        [&function](const resolver::ResolvedSymbol& symbol) {
            return symbol.address == function.address;
        });
    if (same_address != index.symbols.end()) {
        return same_address->name;
    }

    return function.name;
}

std::string error_code_text(ErrorCode code)
{
    switch (code) {
    case ErrorCode::Ok:
        return "ok";
    case ErrorCode::Usage:
        return "usage";
    case ErrorCode::FileIo:
        return "file I/O";
    case ErrorCode::MalformedInput:
        return "malformed input";
    case ErrorCode::UnsupportedFormat:
        return "unsupported format";
    case ErrorCode::NotFound:
        return "not found";
    case ErrorCode::Disassembly:
        return "disassembly";
    case ErrorCode::Resolution:
        return "resolution";
    case ErrorCode::Formatting:
        return "formatting";
    case ErrorCode::Internal:
        return "internal";
    }
    return "unknown";
}

std::string json_escape(std::string_view value)
{
    std::ostringstream out;
    for (const char character : value) {
        const auto byte = static_cast<unsigned char>(character);
        switch (byte) {
        case '"':
            out << "\\\"";
            break;
        case '\\':
            out << "\\\\";
            break;
        case '\b':
            out << "\\b";
            break;
        case '\f':
            out << "\\f";
            break;
        case '\n':
            out << "\\n";
            break;
        case '\r':
            out << "\\r";
            break;
        case '\t':
            out << "\\t";
            break;
        default:
            if (byte < 0x20U) {
                out << "\\u" << std::hex << std::nouppercase << std::setfill('0') << std::setw(4)
                    << static_cast<unsigned int>(byte);
            } else {
                out << static_cast<char>(byte);
            }
            break;
        }
    }
    return out.str();
}

// Escape control characters and truncate a string literal to 64 source characters
// for inline annotation, appending a single-character ellipsis when truncated.
std::string string_preview(const std::string& value)
{
    constexpr std::size_t limit = 64;
    const bool truncated = value.size() > limit;
    const std::size_t count = truncated ? limit : value.size();
    std::string escaped;
    for (std::size_t index = 0; index < count; ++index) {
        const char character = value[index];
        switch (character) {
        case '\n':
            escaped += "\\n";
            break;
        case '\t':
            escaped += "\\t";
            break;
        case '\r':
            escaped += "\\r";
            break;
        case '"':
            escaped += "\\\"";
            break;
        case '\\':
            escaped += "\\\\";
            break;
        default:
            escaped += character;
            break;
        }
    }
    if (truncated) {
        escaped += "…";
    }
    return escaped;
}

std::map<std::uint64_t, std::string> build_labels(
    const std::vector<resolver::AnnotatedInstruction>& instructions)
{
    std::vector<std::uint64_t> targets;
    targets.reserve(instructions.size());
    for (const resolver::AnnotatedInstruction& annotated : instructions) {
        const disasm::Instruction& instruction = annotated.instruction;
        if (!instruction.branch_target.has_value()) {
            continue;
        }
        const std::uint64_t target = instruction.branch_target.value();
        const auto target_instruction = std::find_if(
            instructions.begin(),
            instructions.end(),
            [target](const resolver::AnnotatedInstruction& candidate) {
                return candidate.instruction.address == target;
            });
        if (target_instruction != instructions.end()) {
            targets.push_back(target);
        }
    }

    std::sort(targets.begin(), targets.end());
    targets.erase(std::unique(targets.begin(), targets.end()), targets.end());

    std::map<std::uint64_t, std::string> labels;
    std::uint64_t next_label = 1;
    for (const std::uint64_t target : targets) {
        labels.emplace(target, "L" + std::to_string(next_label));
        ++next_label;
    }
    return labels;
}

std::optional<std::string> preview_for_target(
    const std::vector<resolver::AnnotatedInstruction>& instructions,
    const std::map<std::uint64_t, std::string>& labels,
    std::uint64_t target)
{
    const auto instruction = std::find_if(
        instructions.begin(),
        instructions.end(),
        [target](const resolver::AnnotatedInstruction& candidate) {
            return candidate.instruction.address == target;
        });
    if (instruction == instructions.end()) {
        return std::nullopt;
    }

    const auto label = labels.find(target);
    if (label == labels.end()) {
        return std::nullopt;
    }

    return label->second + ": " + instruction_text(instruction->instruction);
}

void append_symbol_json(std::ostringstream& out, const resolver::ResolvedSymbol& symbol)
{
    out << "{";
    out << "\"name\":\"" << json_escape(symbol.name) << "\",";
    out << "\"raw_name\":\"" << json_escape(symbol.raw_name) << "\",";
    out << "\"address\":\"" << hex_address(symbol.address) << "\",";
    out << "\"size\":" << symbol.size << ",";
    out << "\"exact\":" << (symbol.exact ? "true" : "false") << ",";
    out << "\"dynamic\":" << (symbol.dynamic ? "true" : "false");
    out << "}";
}

void append_reference_json(std::ostringstream& out, const resolver::ResolvedReference& reference)
{
    out << "{";
    out << "\"address\":\"" << hex_address(reference.address) << "\",";
    out << "\"name\":\"" << json_escape(reference.name) << "\",";
    out << "\"raw_name\":\"" << json_escape(reference.raw_name) << "\",";
    out << "\"relocation_section\":\"" << json_escape(reference.relocation_section) << "\",";
    out << "\"relocation_type\":" << reference.relocation_type << ",";
    if (reference.has_addend) {
        out << "\"addend\":" << reference.addend;
    } else {
        out << "\"addend\":null";
    }
    out << "}";
}

} // namespace

Options default_options()
{
    Options options;
    options.no_color_env = std::getenv("NO_COLOR") != nullptr;
    return options;
}

bool color_enabled(const Options& options) noexcept
{
    return options.color && !options.no_color_env;
}

Result<std::string> render_banner()
{
    return Result<std::string>::ok(banner_text());
}

Result<std::string> render_version()
{
    std::ostringstream out;
    out << banner_text() << "\n";
    out << program_name << " " << version_string << "\n";
    out << "  build commit:  " << build_commit << "\n";
    out << "  build date:    " << build_date << "\n";
    out << "  capstone:      " << capstone_version << "\n";
    out << "  formats:       ELF, Mach-O, PE/COFF (parsed); static archive (detected)\n";
    out << "  architectures: x86, x86-64, arm, thumb, aarch64, riscv32, riscv64, "
           "mips, mipsel, mips64, mips64el, ppc, ppc64, ppc64le\n";
    return Result<std::string>::ok(out.str());
}

Result<std::string> render_help()
{
    std::ostringstream out;
    out << banner_text() << "\n";
    out << "Usage:\n";
    out << "  roe <file>                     list functions with preserved addresses\n";
    out << "  roe <file> <symbol>            disassemble one function, symbols resolved\n";
    out << "  roe <file> --section <name>    disassemble a named section\n";
    out << "  roe <file> --all               disassemble every executable section\n\n";

    out << "Input:\n";
    out << "  <file>                 object, executable, shared library, or .o to inspect\n";
    out << "  <symbol>               function name (mangled or demangled) to disassemble\n";
    out << "  --section <name>       disassemble a named section, e.g. .text\n";
    out << "  --all, -D              disassemble every executable section\n";
    out << "  --addr <hex>           disassemble from an address (stripped-safe)\n";
    out << "  --range <a>-<b>        disassemble an inclusive address range\n";
    out << "  --raw-bytes            disassemble bytes from stdin (needs --arch)\n";
    out << "  --hex-input            treat stdin as a hex string (with --raw-bytes)\n";
    out << "  --base <hex>           base address for --raw-bytes (default 0)\n";
    out << "  --arch <name>          override/select the architecture (e.g. thumb, riscv64)\n\n";

    out << "Inspect:\n";
    out << "  --headers              file header: format, arch, type, entry point\n";
    out << "  --sections             sections with size, permissions, offset\n";
    out << "  --segments             program headers / load commands / data directories\n";
    out << "  --imports              imported symbols grouped by library\n";
    out << "  --exports              exported symbols\n";
    out << "  --hex [section]        hex + ASCII dump of a section, --addr, or --range\n";
    out << "  --bytes <n>            byte count for --hex with --addr\n";
    out << "  --strings              extract strings with their referencing instruction\n";
    out << "  --min-len <n>          minimum string length for --strings (default 4)\n";
    out << "  --find <pattern>       fuzzy symbol search across all symbol sources\n\n";

    out << "Filtering & comparison:\n";
    out << "  --grep <regex>         list functions whose name matches a regex\n";
    out << "  --calls <symbol>       list functions that call or branch to a symbol\n";
    out << "  --contains <string>    list functions whose body references a string\n";
    out << "  --xref <symbol>        show every call site of a symbol\n";
    out << "  --stats                per-function size, basic blocks, branches, depth\n";
    out << "  --diff <other>         function-level diff against another binary\n\n";

    out << "Output:\n";
    out << "  --json                 emit machine-readable JSON\n";
    out << "  --no-color             disable ANSI color for pipes and logs\n";
    out << "  --show-bytes           show raw instruction bytes (off by default)\n";
    out << "  --source               interleave source lines from debug info\n";
    out << "  --no-pager             do not page long output through $PAGER\n";
    out << "  --quiet, -q            bare output for pipelines (no headers/decoration)\n";
    out << "  --verbose, -v          extra context; -v -v adds debug to stderr\n\n";

    out << "Workflow:\n";
    out << "  --watch                re-run automatically when the file changes\n";
    out << "  --completions <shell>  emit a completion script (bash|zsh|fish|powershell)\n";
    out << "  --help [topic]         show help; topics: usage formats arches examples config json\n";
    out << "  --version, -V          show version, build info, arches, and formats\n\n";

    out << "Examples:\n";
    out << "  roe vmlinux.o handle_mm_fault          disassemble one function, resolved\n";
    out << "  roe a.out --addr 0x4012a0              disassemble a stripped function\n";
    out << "  roe a.out --imports                    imports grouped by library\n";
    out << "  roe a.out --strings                    strings with their xref\n";
    out << "  roe new.bin --diff old.bin             function-level diff\n";
    out << "  echo '55 48 89 e5 c3' | roe --raw-bytes --arch x86_64\n\n";

    out << "See 'man roe' or https://github.com/USER/roe for the full manual.\n";
    return Result<std::string>::ok(out.str());
}

Result<std::string> render_error(const Error& error, const Options& options)
{
    std::ostringstream out;
    out << colorize("error", ansi_red, options) << ": " << error_code_text(error.code);
    if (!error.message.empty()) {
        out << ": " << error.message;
    }
    if (error.has_offset) {
        out << " at offset " << hex_address(error.offset);
    }
    out << "\n";
    return Result<std::string>::ok(out.str());
}

Result<std::string> render_function_list(
    const elf::File& file,
    const resolver::Index& index,
    const Options& options)
{
    std::vector<elf::Symbol> functions;
    for (const elf::Symbol& symbol : file.symbols) {
        if (symbol.type == elf::SymbolType::Function && symbol.defined) {
            functions.push_back(symbol);
        }
    }
    std::sort(functions.begin(), functions.end(), [](const elf::Symbol& lhs, const elf::Symbol& rhs) {
        if (lhs.address == rhs.address) {
            return lhs.name < rhs.name;
        }
        return lhs.address < rhs.address;
    });

    std::ostringstream out;
    if (!options.quiet) {
        out << colorize("Functions", ansi_bold, options) << " in " << file.source_name << "\n";
    }
    if (functions.empty() && !index.symbols.empty()) {
        std::vector<resolver::ResolvedSymbol> symbols = index.symbols;
        std::sort(
            symbols.begin(),
            symbols.end(),
            [](const resolver::ResolvedSymbol& lhs, const resolver::ResolvedSymbol& rhs) {
                if (lhs.address == rhs.address) {
                    return lhs.name < rhs.name;
                }
                return lhs.address < rhs.address;
            });
        for (const resolver::ResolvedSymbol& symbol : symbols) {
            out << padded_hex_address(symbol.address) << "  ";
            out << std::setw(8) << std::dec << symbol.size << "  " << symbol.name;
            if (symbol.dynamic && !options.quiet) {
                out << " " << colorize("[dyn]", ansi_dim, options);
            }
            out << "\n";
        }
        return Result<std::string>::ok(out.str());
    }

    for (const elf::Symbol& function : functions) {
        out << padded_hex_address(function.address) << "  ";
        out << std::setw(8) << std::dec << function.size << "  ";
        out << display_name_for_function(function, index);
        if (function.dynamic && !options.quiet) {
            out << " " << colorize("[dyn]", ansi_dim, options);
        }
        out << "\n";
    }
    return Result<std::string>::ok(out.str());
}

Result<std::string> render_function_list(
    const binary::FileView& file,
    const resolver::Index& index,
    const Options& options)
{
    const std::optional<binary::Object> object = binary::primary_object(file);
    std::vector<binary::Symbol> functions;
    if (object.has_value()) {
        for (const binary::Symbol& symbol : object->symbols) {
            if (symbol.type == binary::SymbolType::Function && symbol.defined) {
                functions.push_back(symbol);
            }
        }
    }
    std::sort(functions.begin(), functions.end(), [](const binary::Symbol& lhs, const binary::Symbol& rhs) {
        if (lhs.address == rhs.address) {
            return lhs.name < rhs.name;
        }
        return lhs.address < rhs.address;
    });

    const auto display_for = [&index](const binary::Symbol& function) -> std::string {
        for (const resolver::ResolvedSymbol& symbol : index.symbols) {
            if (symbol.address == function.address && symbol.raw_name == function.raw_name) {
                return symbol.name;
            }
        }
        for (const resolver::ResolvedSymbol& symbol : index.symbols) {
            if (symbol.address == function.address) {
                return symbol.name;
            }
        }
        return function.name;
    };

    std::ostringstream out;
    if (!options.quiet) {
        out << colorize("Functions", ansi_bold, options) << " in " << file.source_name << "\n";
    }
    if (functions.empty() && !index.symbols.empty()) {
        std::vector<resolver::ResolvedSymbol> symbols = index.symbols;
        std::sort(symbols.begin(), symbols.end(),
            [](const resolver::ResolvedSymbol& lhs, const resolver::ResolvedSymbol& rhs) {
                if (lhs.address == rhs.address) {
                    return lhs.name < rhs.name;
                }
                return lhs.address < rhs.address;
            });
        for (const resolver::ResolvedSymbol& symbol : symbols) {
            out << padded_hex_address(symbol.address) << "  ";
            out << std::setw(8) << std::dec << symbol.size << "  " << symbol.name;
            if (symbol.dynamic && !options.quiet) {
                out << " " << colorize("[dyn]", ansi_dim, options);
            }
            out << "\n";
        }
        return Result<std::string>::ok(out.str());
    }

    for (const binary::Symbol& function : functions) {
        out << padded_hex_address(function.address) << "  ";
        out << std::setw(8) << std::dec << function.size << "  ";
        out << display_for(function);
        if (function.dynamic && !options.quiet) {
            out << " " << colorize("[dyn]", ansi_dim, options);
        }
        out << "\n";
    }
    return Result<std::string>::ok(out.str());
}

Result<std::string> render_function_table(
    std::string_view heading,
    const std::vector<binary::Symbol>& functions,
    const resolver::Index& index,
    const Options& options)
{
    std::vector<binary::Symbol> sorted = functions;
    std::sort(sorted.begin(), sorted.end(), [](const binary::Symbol& lhs, const binary::Symbol& rhs) {
        if (lhs.address == rhs.address) {
            return lhs.name < rhs.name;
        }
        return lhs.address < rhs.address;
    });

    const auto display_for = [&index](const binary::Symbol& function) -> std::string {
        for (const resolver::ResolvedSymbol& symbol : index.symbols) {
            if (symbol.address == function.address && symbol.raw_name == function.raw_name) {
                return symbol.name;
            }
        }
        return function.name;
    };

    std::ostringstream out;
    if (!options.quiet) {
        out << colorize(heading, ansi_bold, options) << "\n";
    }
    for (const binary::Symbol& function : sorted) {
        out << padded_hex_address(function.address) << "  ";
        out << std::setw(8) << std::dec << function.size << "  " << display_for(function);
        if (function.dynamic && !options.quiet) {
            out << " " << colorize("[dyn]", ansi_dim, options);
        }
        out << "\n";
    }
    return Result<std::string>::ok(out.str());
}

Result<std::string> render_disassembly(
    const std::vector<resolver::AnnotatedInstruction>& instructions,
    const Options& options)
{
    const std::map<std::uint64_t, std::string> labels = build_labels(instructions);
    std::ostringstream out;
    std::string last_source_key;

    for (const resolver::AnnotatedInstruction& annotated : instructions) {
        const disasm::Instruction& instruction = annotated.instruction;

        if (options.source && annotated.source_line != 0U) {
            const std::string key = annotated.source_path + ":" + std::to_string(annotated.source_line);
            if (key != last_source_key) {
                last_source_key = key;
                const auto slash = annotated.source_path.find_last_of('/');
                const std::string file = slash == std::string::npos ? annotated.source_path
                                                                    : annotated.source_path.substr(slash + 1);
                std::string head = "; " + (file.empty() ? std::string("source") : file) + ":"
                    + std::to_string(annotated.source_line);
                out << colorize(head, ansi_dim, options);
                if (annotated.source_text.has_value() && !annotated.source_text->empty()) {
                    out << "  " << annotated.source_text.value();
                }
                out << "\n";
            }
        }

        const auto label = labels.find(instruction.address);
        if (label != labels.end()) {
            out << colorize(label->second, ansi_yellow, options) << ":\n";
        }

        out << colorize(padded_hex_address(instruction.address), ansi_dim, options) << ": ";
        if (options.show_bytes) {
            const std::string bytes = bytes_text(instruction.bytes);
            if (!bytes.empty()) {
                out << std::left << std::setw(23) << bytes << std::right;
            } else {
                out << std::left << std::setw(23) << "" << std::right;
            }
        }

        out << colorize(instruction.mnemonic, ansi_green, options);

        bool branch_target_is_in_current_output = false;
        std::optional<std::string> preview;
        if (instruction.branch_target.has_value()) {
            const std::uint64_t target = instruction.branch_target.value();
            branch_target_is_in_current_output = labels.find(target) != labels.end();
            preview = preview_for_target(instructions, labels, target);
        }

        if (instruction.branch_target.has_value() && !branch_target_is_in_current_output &&
            annotated.branch_target_symbol.has_value()) {
            out << ' ' << annotated.branch_target_symbol->name;
        } else if (instruction.branch_target.has_value()) {
            const std::uint64_t target = instruction.branch_target.value();
            const std::string target_text = hex_address(target);
            if (instruction.operands.find(target_text) != std::string::npos) {
                // The operand string already shows the absolute target (x86, ARM64, PPC).
                out << ' ' << instruction.operands;
            } else {
                // The operand string carries a relative displacement (RISC-V, MIPS);
                // rewrite the trailing immediate as the resolved absolute target.
                const auto comma = instruction.operands.rfind(", ");
                const std::string last_token = comma == std::string::npos
                    ? instruction.operands
                    : instruction.operands.substr(comma + 2);
                if (looks_like_immediate(last_token)) {
                    const std::string prefix =
                        comma == std::string::npos ? std::string{} : instruction.operands.substr(0, comma);
                    if (!prefix.empty()) {
                        out << ' ' << prefix << ", " << target_text;
                    } else {
                        out << ' ' << target_text;
                    }
                } else {
                    if (!instruction.operands.empty()) {
                        out << ' ' << instruction.operands;
                    }
                    out << ' ' << target_text;
                }
            }
        } else if (!instruction.operands.empty()) {
            out << ' ' << instruction.operands;
        }

        if (preview.has_value()) {
            out << " \u2192 [" << preview.value() << "]";
        }
        if (instruction.branch_target.has_value() && !branch_target_is_in_current_output &&
            annotated.branch_target_symbol.has_value()) {
            out << "  " << colorize("; ", ansi_cyan, options) << "@" << hex_address(instruction.branch_target.value());
        }
        if (annotated.reference.has_value()) {
            out << "  " << colorize("; ref ", ansi_cyan, options) << annotated.reference->name;
            out << " @" << hex_address(annotated.reference->address);
            if (options.verbose >= 1 && !annotated.reference->relocation_section.empty()) {
                out << " " << colorize("[" + annotated.reference->relocation_section + "]", ansi_dim, options);
            }
        }
        if (annotated.string_reference.has_value()) {
            out << "  " << colorize("; ", ansi_cyan, options) << "\""
                << string_preview(annotated.string_reference->value) << "\"";
        }
        if (annotated.symbol.has_value() && annotated.symbol->exact) {
            out << "  " << colorize("; sym ", ansi_cyan, options) << annotated.symbol->name;
        }
        out << "\n";
    }

    return Result<std::string>::ok(out.str());
}

Result<std::string> render_json(
    const std::vector<resolver::AnnotatedInstruction>& instructions,
    const Options& /*options*/)
{
    const std::map<std::uint64_t, std::string> labels = build_labels(instructions);
    std::ostringstream out;
    out << "{\n";
    out << "  \"instructions\": [\n";

    for (std::size_t index = 0; index < instructions.size(); ++index) {
        const resolver::AnnotatedInstruction& annotated = instructions[index];
        const disasm::Instruction& instruction = annotated.instruction;
        const auto label = labels.find(instruction.address);
        out << "    {\n";
        out << "      \"address\": \"" << hex_address(instruction.address) << "\",\n";
        out << "      \"size\": " << static_cast<unsigned int>(instruction.size) << ",\n";
        out << "      \"bytes\": [";
        for (std::size_t byte_index = 0; byte_index < instruction.bytes.size(); ++byte_index) {
            if (byte_index != 0) {
                out << ", ";
            }
            out << static_cast<unsigned int>(instruction.bytes[byte_index]);
        }
        out << "],\n";
        out << "      \"mnemonic\": \"" << json_escape(instruction.mnemonic) << "\",\n";
        out << "      \"operands\": \"" << json_escape(instruction.operands) << "\",\n";
        if (label != labels.end()) {
            out << "      \"label\": \"" << label->second << "\",\n";
        } else {
            out << "      \"label\": null,\n";
        }
        if (instruction.branch_target.has_value()) {
            const std::uint64_t target = instruction.branch_target.value();
            out << "      \"branch_target\": \"" << hex_address(target) << "\",\n";
            const std::optional<std::string> preview = preview_for_target(instructions, labels, target);
            if (preview.has_value()) {
                out << "      \"branch_preview\": \"" << json_escape(preview.value()) << "\",\n";
            } else {
                out << "      \"branch_preview\": null,\n";
            }
        } else {
            out << "      \"branch_target\": null,\n";
            out << "      \"branch_preview\": null,\n";
        }
        out << "      \"symbol\": ";
        if (annotated.symbol.has_value()) {
            append_symbol_json(out, annotated.symbol.value());
        } else {
            out << "null";
        }
        out << ",\n";
        out << "      \"reference\": ";
        if (annotated.reference.has_value()) {
            append_reference_json(out, annotated.reference.value());
        } else {
            out << "null";
        }
        out << ",\n";
        out << "      \"string_reference\": ";
        if (annotated.string_reference.has_value()) {
            out << "\"" << json_escape(annotated.string_reference->value) << "\"";
        } else {
            out << "null";
        }
        out << "\n";
        out << "    }";
        if (index + 1U != instructions.size()) {
            out << ",";
        }
        out << "\n";
    }

    out << "  ]\n";
    out << "}\n";
    return Result<std::string>::ok(out.str());
}

Result<std::string> render_help_topic(const std::string& topic)
{
    std::ostringstream out;
    if (topic == "usage") {
        out << "Usage:\n";
        out << "  roe <file>                     list functions\n";
        out << "  roe <file> <symbol>            disassemble one function\n";
        out << "  roe <file> --section <name>    disassemble a section\n";
        out << "  roe <file> --all               disassemble all executable sections\n";
        out << "  roe <file> --xref <symbol>     show call sites of a symbol\n";
        out << "  roe <file> --stats             per-function statistics\n";
    } else if (topic == "formats") {
        out << "Supported container formats (detected by magic bytes, not extension):\n";
        out << "  ELF              parsed: ELF32/64, little/big endian, executables, .so, .o\n";
        out << "  Mach-O           parsed: x86-64 and ARM64, thin and fat/universal\n";
        out << "  PE/COFF          parsed: x86, x86-64, ARM64; .exe and .dll\n";
        out << "  static archive   recognized; extract members and inspect them individually\n";
    } else if (topic == "arches") {
        out << "Disassembly architectures (Capstone-backed):\n";
        out << "  x86, x86-64                fully verified\n";
        out << "  aarch64 (ARM64)            fully verified\n";
        out << "  arm, thumb                 supported (use --arch thumb for Thumb code)\n";
        out << "  riscv32, riscv64           supported (compressed instructions enabled)\n";
        out << "  mips, mipsel, mips64, mips64el   supported\n";
        out << "  ppc, ppc64, ppc64le        supported\n";
    } else if (topic == "examples") {
        out << "Examples:\n";
        out << "  roe vmlinux.o                          list every function\n";
        out << "  roe vmlinux.o handle_mm_fault          disassemble one function\n";
        out << "  roe a.out main --show-bytes            include raw instruction bytes\n";
        out << "  roe a.out main --json | jq .           machine-readable output\n";
        out << "  roe libfoo.so --grep '::'              find C++ methods\n";
        out << "  roe a.out --calls printf               functions that call printf\n";
        out << "  roe a.out --xref malloc                every call site of malloc\n";
        out << "  roe a.out --stats                      per-function statistics\n";
        out << "  roe a.out --addr 0x4012a0              disassemble a stripped function\n";
        out << "  roe a.out --imports                    imports grouped by library\n";
        out << "  roe a.out --hex .rodata                hex + ASCII dump of a section\n";
        out << "  roe a.out --strings                    strings with their xref\n";
        out << "  roe new.bin --diff old.bin             function-level diff\n";
        out << "  echo '55 48 89 e5 c3' | roe --raw-bytes --arch x86_64\n";
    } else if (topic == "config") {
        out << "Configuration file (CLI flags always override):\n";
        out << "  Linux:    $XDG_CONFIG_HOME/roe/config.toml  (default ~/.config/roe/config.toml)\n";
        out << "  macOS:    ~/Library/Application Support/roe/config.toml\n";
        out << "  Windows:  %APPDATA%\\roe\\config.toml\n";
        out << "  Override: set ROE_CONFIG to an explicit path\n";
        out << "Keys: color, pager, show_bytes, source, syntax. See docs/CONFIG.md.\n";
    } else if (topic == "json") {
        out << "JSON output (--json):\n";
        out << "  Disassembly: { \"instructions\": [ { address, size, bytes, mnemonic,\n";
        out << "    operands, label, branch_target, branch_preview, symbol, reference } ] }\n";
        out << "  Addresses are 0x-prefixed hex strings; sizes are integers.\n";
        out << "  See docs/JSON_SCHEMA.md for the full, stable schema.\n";
    } else {
        return Result<std::string>::err(
            {ErrorCode::Usage,
             "unknown help topic: " + topic + " (try usage, formats, arches, examples, config, json)"});
    }
    return Result<std::string>::ok(out.str());
}

Result<std::string> render_completions(const std::string& shell)
{
    static constexpr std::string_view flags =
        "--section --all -D --addr --range --raw-bytes --hex-input --base --arch "
        "--headers --sections --segments --imports --exports --hex --bytes --strings --min-len --find "
        "--grep --calls --contains --xref --stats --diff "
        "--json --no-color --show-bytes --source --no-pager --quiet -q --verbose -v --watch --completions "
        "--help -h --version -V";
    std::ostringstream out;
    if (shell == "bash") {
        out << "# roe bash completion. Source this file or place it in your bash-completion dir.\n";
        out << "_roe() {\n";
        out << "    local cur=\"${COMP_WORDS[COMP_CWORD]}\"\n";
        out << "    if [[ \"$cur\" == -* ]]; then\n";
        out << "        COMPREPLY=( $(compgen -W \"" << flags << "\" -- \"$cur\") )\n";
        out << "    else\n";
        out << "        COMPREPLY=( $(compgen -f -- \"$cur\") )\n";
        out << "    fi\n";
        out << "}\n";
        out << "complete -F _roe roe\n";
    } else if (shell == "zsh") {
        out << "#compdef roe\n";
        out << "# roe zsh completion. Place on your $fpath as _roe.\n";
        out << "_roe() {\n";
        out << "    local -a opts\n";
        out << "    opts=(" << flags << ")\n";
        out << "    _arguments '*: :->args' && return\n";
        out << "    if [[ $words[CURRENT] == -* ]]; then\n";
        out << "        compadd -- ${opts}\n";
        out << "    else\n";
        out << "        _files\n";
        out << "    fi\n";
        out << "}\n";
        out << "_roe \"$@\"\n";
    } else if (shell == "fish") {
        out << "# roe fish completion.\n";
        out << "complete -c roe -l section -d 'Disassemble a named section'\n";
        out << "complete -c roe -l all -s D -d 'Disassemble all executable sections'\n";
        out << "complete -c roe -l addr -d 'Disassemble from an address'\n";
        out << "complete -c roe -l range -d 'Disassemble an address range'\n";
        out << "complete -c roe -l raw-bytes -d 'Disassemble bytes from stdin'\n";
        out << "complete -c roe -l hex-input -d 'Treat stdin as hex'\n";
        out << "complete -c roe -l base -d 'Base address for raw bytes'\n";
        out << "complete -c roe -l arch -d 'Override architecture'\n";
        out << "complete -c roe -l headers -d 'Show the file header'\n";
        out << "complete -c roe -l sections -d 'List sections'\n";
        out << "complete -c roe -l segments -d 'List segments'\n";
        out << "complete -c roe -l imports -d 'List imported symbols'\n";
        out << "complete -c roe -l exports -d 'List exported symbols'\n";
        out << "complete -c roe -l hex -d 'Hex + ASCII dump'\n";
        out << "complete -c roe -l bytes -d 'Byte count for --hex'\n";
        out << "complete -c roe -l strings -d 'Extract strings with xref'\n";
        out << "complete -c roe -l min-len -d 'Minimum string length'\n";
        out << "complete -c roe -l find -d 'Fuzzy symbol search'\n";
        out << "complete -c roe -l diff -d 'Function-level diff'\n";
        out << "complete -c roe -l quiet -s q -d 'Bare output for pipelines'\n";
        out << "complete -c roe -l verbose -s v -d 'Extra context'\n";
        out << "complete -c roe -l grep -d 'Filter functions by name regex'\n";
        out << "complete -c roe -l calls -d 'Functions that call a symbol'\n";
        out << "complete -c roe -l contains -d 'Functions referencing a string'\n";
        out << "complete -c roe -l xref -d 'Call sites of a symbol'\n";
        out << "complete -c roe -l stats -d 'Per-function statistics'\n";
        out << "complete -c roe -l json -d 'Machine-readable JSON'\n";
        out << "complete -c roe -l no-color -d 'Disable color'\n";
        out << "complete -c roe -l show-bytes -d 'Show raw instruction bytes'\n";
        out << "complete -c roe -l source -d 'Interleave source lines'\n";
        out << "complete -c roe -l no-pager -d 'Disable the pager'\n";
        out << "complete -c roe -l watch -d 'Re-run on file change'\n";
        out << "complete -c roe -l completions -d 'Emit a shell completion script'\n";
        out << "complete -c roe -l help -s h -d 'Show help'\n";
        out << "complete -c roe -l version -s V -d 'Show version'\n";
    } else if (shell == "powershell") {
        out << "# roe PowerShell completion. Add to your profile.\n";
        out << "Register-ArgumentCompleter -Native -CommandName roe -ScriptBlock {\n";
        out << "    param($wordToComplete, $commandAst, $cursorPosition)\n";
        out << "    $opts = @('" << "--section','--all','--addr','--range','--raw-bytes','--base','--arch',"
            << "'--headers','--sections','--segments','--imports','--exports','--hex','--bytes','--strings',"
            << "'--min-len','--find','--grep','--calls','--contains','--xref','--stats','--diff',"
            << "'--json','--no-color','--show-bytes','--source','--no-pager','--quiet','--verbose',"
            << "'--watch','--completions','--help','--version')\n";
        out << "    $opts | Where-Object { $_ -like \"$wordToComplete*\" } | ForEach-Object {\n";
        out << "        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterName', $_)\n";
        out << "    }\n";
        out << "}\n";
    } else {
        return Result<std::string>::err(
            {ErrorCode::Usage, "unknown shell: " + shell + " (try bash, zsh, fish, powershell)"});
    }
    return Result<std::string>::ok(out.str());
}

Result<std::string> render_xrefs(const std::vector<features::Xref>& xrefs, const Options& options)
{
    std::ostringstream out;
    if (options.mode == Mode::Json) {
        out << "{\n  \"xrefs\": [\n";
        for (std::size_t index = 0; index < xrefs.size(); ++index) {
            const features::Xref& xref = xrefs[index];
            out << "    {";
            out << "\"from\":\"" << json_escape(xref.from_function) << "\",";
            out << "\"from_address\":\"" << hex_address(xref.from_function_address) << "\",";
            out << "\"address\":\"" << hex_address(xref.instruction_address) << "\",";
            out << "\"target\":\"" << json_escape(xref.target_name) << "\",";
            out << "\"target_address\":\"" << hex_address(xref.target_address) << "\",";
            out << "\"instruction\":\"" << json_escape(xref.instruction_text) << "\"";
            out << "}" << (index + 1U < xrefs.size() ? "," : "") << "\n";
        }
        out << "  ]\n}\n";
        return Result<std::string>::ok(out.str());
    }

    if (xrefs.empty()) {
        out << "no references found\n";
        return Result<std::string>::ok(out.str());
    }
    out << colorize("References to ", ansi_bold, options) << xrefs.front().target_name << " ("
        << xrefs.size() << ")\n";
    for (const features::Xref& xref : xrefs) {
        out << colorize(padded_hex_address(xref.instruction_address), ansi_dim, options) << "  ";
        out << colorize(xref.from_function, ansi_green, options) << "  " << xref.instruction_text << "\n";
    }
    return Result<std::string>::ok(out.str());
}

Result<std::string> render_stats(const std::vector<features::FunctionStats>& stats, const Options& options)
{
    std::ostringstream out;
    if (options.mode == Mode::Json) {
        out << "{\n  \"stats\": [\n";
        for (std::size_t index = 0; index < stats.size(); ++index) {
            const features::FunctionStats& entry = stats[index];
            out << "    {";
            out << "\"name\":\"" << json_escape(entry.name) << "\",";
            out << "\"address\":\"" << hex_address(entry.address) << "\",";
            out << "\"size\":" << entry.size << ",";
            out << "\"basic_blocks\":" << entry.basic_blocks << ",";
            out << "\"branch_count\":" << entry.branch_count << ",";
            out << "\"max_nesting_depth\":" << entry.max_nesting_depth;
            out << "}" << (index + 1U < stats.size() ? "," : "") << "\n";
        }
        out << "  ]\n}\n";
        return Result<std::string>::ok(out.str());
    }

    out << colorize("Statistics", ansi_bold, options) << "\n";
    out << "      size  blocks  branch  depth  function\n";
    for (const features::FunctionStats& entry : stats) {
        out << std::right << std::setw(10) << std::dec << entry.size << "  ";
        out << std::setw(6) << entry.basic_blocks << "  ";
        out << std::setw(6) << entry.branch_count << "  ";
        out << std::setw(5) << entry.max_nesting_depth << "  ";
        out << entry.name << "\n";
    }
    return Result<std::string>::ok(out.str());
}

Result<std::string> render_sections(const binary::FileView& file, const Options& options)
{
    const std::optional<binary::Object> object = binary::primary_object(file);
    std::ostringstream out;
    if (options.mode == Mode::Json) {
        out << "{\n  \"sections\": [\n";
        const std::vector<binary::Section> sections = object.has_value() ? object->sections : std::vector<binary::Section>{};
        for (std::size_t index = 0; index < sections.size(); ++index) {
            const binary::Section& section = sections[index];
            out << "    {";
            out << "\"name\":\"" << json_escape(section.name) << "\",";
            out << "\"address\":\"" << hex_address(section.address) << "\",";
            out << "\"size\":" << section.size << ",";
            out << "\"readable\":" << (section.readable ? "true" : "false") << ",";
            out << "\"writable\":" << (section.writable ? "true" : "false") << ",";
            out << "\"executable\":" << (section.executable ? "true" : "false");
            out << "}" << (index + 1U < sections.size() ? "," : "") << "\n";
        }
        out << "  ]\n}\n";
        return Result<std::string>::ok(out.str());
    }

    out << colorize("Sections", ansi_bold, options) << " in " << file.source_name << "\n";
    if (object.has_value()) {
        for (const binary::Section& section : object->sections) {
            const std::string flags = std::string(section.readable ? "r" : "-") +
                                      (section.writable ? "w" : "-") + (section.executable ? "x" : "-");
            out << padded_hex_address(section.address) << "  ";
            out << std::right << std::setw(10) << std::dec << section.size << "  ";
            out << flags << "  " << section.name << "\n";
        }
    }
    return Result<std::string>::ok(out.str());
}

namespace {
std::string object_kind_name(binary::ObjectKind kind)
{
    switch (kind) {
    case binary::ObjectKind::Relocatable:
        return "relocatable";
    case binary::ObjectKind::Executable:
        return "executable";
    case binary::ObjectKind::SharedLibrary:
        return "shared library";
    case binary::ObjectKind::StaticArchive:
        return "static archive";
    case binary::ObjectKind::Object:
        return "object";
    case binary::ObjectKind::Unknown:
        break;
    }
    return "unknown";
}
} // namespace

Result<std::string> render_headers(const binary::FileView& file, const Options& options)
{
    const std::optional<binary::Object> object = binary::primary_object(file);
    std::ostringstream out;
    if (options.mode == Mode::Json) {
        out << "{\n";
        out << "  \"format\": \"" << json_escape(std::string(binary::format_name(file.format))) << "\",\n";
        if (object.has_value()) {
            out << "  \"architecture\": \"" << binary::architecture_name(object->architecture) << "\",\n";
            out << "  \"type\": \"" << object_kind_name(object->kind) << "\",\n";
            out << "  \"endianness\": \"" << (object->endianness == binary::Endianness::Big ? "big" : "little") << "\",\n";
            out << "  \"bits\": " << (object->address_width == binary::AddressWidth::Bits64 ? 64 : 32) << ",\n";
            out << "  \"entry\": \"" << hex_address(object->entry) << "\"\n";
        } else {
            out << "  \"architecture\": null\n";
        }
        out << "}\n";
        return Result<std::string>::ok(out.str());
    }
    out << colorize("Header", ansi_bold, options) << " of " << file.source_name << "\n";
    out << "  format:        " << binary::format_name(file.format) << "\n";
    if (object.has_value()) {
        out << "  architecture:  " << binary::architecture_name(object->architecture) << "\n";
        out << "  type:          " << object_kind_name(object->kind) << "\n";
        out << "  endianness:    " << (object->endianness == binary::Endianness::Big ? "big" : "little") << "\n";
        out << "  address width: " << (object->address_width == binary::AddressWidth::Bits64 ? "64-bit" : "32-bit") << "\n";
        out << "  entry point:   " << hex_address(object->entry) << "\n";
    }
    return Result<std::string>::ok(out.str());
}

Result<std::string> render_segments(const binary::FileView& file, const Options& options)
{
    const std::optional<binary::Object> object = binary::primary_object(file);
    const std::vector<binary::Segment> segments = object.has_value() ? object->segments : std::vector<binary::Segment>{};
    std::ostringstream out;
    if (options.mode == Mode::Json) {
        out << "{\n  \"segments\": [\n";
        for (std::size_t i = 0; i < segments.size(); ++i) {
            const binary::Segment& segment = segments[i];
            out << "    {\"name\":\"" << json_escape(segment.name) << "\",\"address\":\"" << hex_address(segment.address)
                << "\",\"offset\":\"" << hex_address(segment.offset) << "\",\"size\":" << segment.size
                << ",\"readable\":" << (segment.readable ? "true" : "false")
                << ",\"writable\":" << (segment.writable ? "true" : "false")
                << ",\"executable\":" << (segment.executable ? "true" : "false") << "}"
                << (i + 1U < segments.size() ? "," : "") << "\n";
        }
        out << "  ]\n}\n";
        return Result<std::string>::ok(out.str());
    }
    out << colorize("Segments", ansi_bold, options) << " in " << file.source_name << "\n";
    for (const binary::Segment& segment : segments) {
        const std::string perms = std::string(segment.readable ? "r" : "-") + (segment.writable ? "w" : "-") +
                                  (segment.executable ? "x" : "-");
        out << padded_hex_address(segment.address) << "  " << std::right << std::setw(10) << std::dec << segment.size
            << "  " << perms << "  " << segment.name << "\n";
    }
    return Result<std::string>::ok(out.str());
}

Result<std::string> render_imports(const binary::FileView& file, const Options& options)
{
    const std::optional<binary::Object> object = binary::primary_object(file);
    std::vector<binary::Symbol> imports;
    std::vector<std::string> libraries;
    if (object.has_value()) {
        libraries = object->libraries;
        for (const binary::Symbol& symbol : object->symbols) {
            if (symbol.bind == binary::SymbolBind::Imported && !symbol.name.empty()) {
                imports.push_back(symbol);
            }
        }
    }
    std::sort(imports.begin(), imports.end(), [](const binary::Symbol& a, const binary::Symbol& b) {
        if (a.library != b.library) {
            return a.library < b.library;
        }
        return a.name < b.name;
    });

    if (options.mode == Mode::Json) {
        std::ostringstream out;
        out << "{\n  \"libraries\": [";
        for (std::size_t i = 0; i < libraries.size(); ++i) {
            out << (i ? ", " : "") << "\"" << json_escape(libraries[i]) << "\"";
        }
        out << "],\n  \"imports\": [\n";
        for (std::size_t i = 0; i < imports.size(); ++i) {
            out << "    {\"name\":\"" << json_escape(imports[i].name) << "\",\"library\":\""
                << json_escape(imports[i].library) << "\"}" << (i + 1U < imports.size() ? "," : "") << "\n";
        }
        out << "  ]\n}\n";
        return Result<std::string>::ok(out.str());
    }

    std::ostringstream out;
    out << colorize("Imports", ansi_bold, options) << " in " << file.source_name << "\n";
    if (!libraries.empty()) {
        out << "  libraries: ";
        for (std::size_t i = 0; i < libraries.size(); ++i) {
            out << (i ? ", " : "") << libraries[i];
        }
        out << "\n";
    }
    std::string current_library = "\x01"; // sentinel so the first group always prints
    for (const binary::Symbol& symbol : imports) {
        if (symbol.library != current_library) {
            current_library = symbol.library;
            out << "  " << colorize(current_library.empty() ? "(unbound)" : current_library, ansi_cyan, options) << ":\n";
        }
        out << "    " << symbol.name << "\n";
    }
    if (imports.empty()) {
        out << "  (no imports)\n";
    }
    return Result<std::string>::ok(out.str());
}

Result<std::string> render_exports(const binary::FileView& file, const Options& options)
{
    const std::optional<binary::Object> object = binary::primary_object(file);
    std::vector<binary::Symbol> exports;
    if (object.has_value()) {
        for (const binary::Symbol& symbol : object->symbols) {
            if (symbol.bind == binary::SymbolBind::Exported) {
                exports.push_back(symbol);
            }
        }
    }
    std::sort(exports.begin(), exports.end(),
        [](const binary::Symbol& a, const binary::Symbol& b) { return a.name < b.name; });

    if (options.mode == Mode::Json) {
        std::ostringstream out;
        out << "{\n  \"exports\": [\n";
        for (std::size_t i = 0; i < exports.size(); ++i) {
            out << "    {\"name\":\"" << json_escape(exports[i].name) << "\",\"address\":\""
                << hex_address(exports[i].address) << "\"}" << (i + 1U < exports.size() ? "," : "") << "\n";
        }
        out << "  ]\n}\n";
        return Result<std::string>::ok(out.str());
    }

    std::ostringstream out;
    out << colorize("Exports", ansi_bold, options) << " in " << file.source_name << "\n";
    for (const binary::Symbol& symbol : exports) {
        out << padded_hex_address(symbol.address) << "  " << symbol.name << "\n";
    }
    if (exports.empty()) {
        out << "  (no exports)\n";
    }
    return Result<std::string>::ok(out.str());
}

Result<std::string> render_hex(const std::vector<std::uint8_t>& bytes, std::uint64_t base, const Options& options)
{
    std::ostringstream out;
    for (std::size_t row = 0; row < bytes.size(); row += 16) {
        out << colorize(padded_hex_address(base + row), ansi_dim, options) << "  ";
        std::string ascii;
        for (std::size_t col = 0; col < 16; ++col) {
            if (row + col < bytes.size()) {
                const std::uint8_t byte = bytes[row + col];
                out << std::hex << std::nouppercase << std::setfill('0') << std::setw(2)
                    << static_cast<unsigned int>(byte) << ' ' << std::dec;
                const bool printable = byte >= 0x20U && byte < 0x7fU;
                const char glyph = printable ? static_cast<char>(byte) : '.';
                if (printable && color_enabled(options)) {
                    ascii += colorize(std::string(1, glyph), ansi_green, options);
                } else {
                    ascii += glyph;
                }
            } else {
                out << "   ";
            }
            if (col == 7) {
                out << ' ';
            }
        }
        out << " |" << ascii << "|\n";
    }
    if (bytes.empty()) {
        out << "(no bytes)\n";
    }
    return Result<std::string>::ok(out.str());
}

Result<std::string> render_strings(const std::vector<features::StringRef>& refs, const Options& options)
{
    std::ostringstream out;
    if (options.mode == Mode::Json) {
        out << "{\n  \"strings\": [\n";
        for (std::size_t i = 0; i < refs.size(); ++i) {
            const features::StringRef& ref = refs[i];
            out << "    {\"address\":\"" << hex_address(ref.address) << "\",\"value\":\"" << json_escape(ref.value)
                << "\",\"referenced\":" << (ref.referenced ? "true" : "false");
            if (ref.referenced) {
                out << ",\"from\":\"" << json_escape(ref.from_function) << "\",\"from_address\":\""
                    << hex_address(ref.from_address) << "\"";
            }
            out << "}" << (i + 1U < refs.size() ? "," : "") << "\n";
        }
        out << "  ]\n}\n";
        return Result<std::string>::ok(out.str());
    }
    for (const features::StringRef& ref : refs) {
        out << colorize(padded_hex_address(ref.address), ansi_dim, options) << "  \""
            << string_preview(ref.value) << "\"";
        if (ref.referenced) {
            out << "   " << colorize("used in: ", ansi_cyan, options) << ref.from_function << " @ "
                << hex_address(ref.from_address);
        } else {
            out << "   " << colorize("(no xref found)", ansi_dim, options);
        }
        out << "\n";
    }
    return Result<std::string>::ok(out.str());
}

Result<std::string> render_find(
    const std::vector<features::FindMatch>& matches, const std::string& pattern, const Options& options)
{
    std::ostringstream out;
    if (options.mode == Mode::Json) {
        out << "{\n  \"pattern\": \"" << json_escape(pattern) << "\",\n  \"matches\": [\n";
        for (std::size_t i = 0; i < matches.size(); ++i) {
            out << "    {\"name\":\"" << json_escape(matches[i].name) << "\",\"address\":\""
                << hex_address(matches[i].address) << "\",\"source\":\"" << matches[i].source << "\"}"
                << (i + 1U < matches.size() ? "," : "") << "\n";
        }
        out << "  ]\n}\n";
        return Result<std::string>::ok(out.str());
    }
    out << colorize("Symbols matching", ansi_bold, options) << " \"" << pattern << "\" (" << matches.size() << ")\n";
    for (const features::FindMatch& match : matches) {
        out << colorize(padded_hex_address(match.address), ansi_dim, options) << "  "
            << colorize("[" + match.source + "]", ansi_cyan, options) << "  " << match.name << "\n";
    }
    return Result<std::string>::ok(out.str());
}

Result<std::string> render_diff(const features::DiffResult& result, const Options& options)
{
    std::ostringstream out;
    if (options.mode == Mode::Json) {
        const auto array = [&](const std::vector<std::string>& items) {
            std::string text = "[";
            for (std::size_t i = 0; i < items.size(); ++i) {
                text += (i ? ", " : "");
                text += "\"" + json_escape(items[i]) + "\"";
            }
            text += "]";
            return text;
        };
        out << "{\n";
        out << "  \"added\": " << array(result.added) << ",\n";
        out << "  \"removed\": " << array(result.removed) << ",\n";
        out << "  \"changed\": " << array(result.changed) << ",\n";
        out << "  \"unchanged\": " << result.unchanged << "\n";
        out << "}\n";
        return Result<std::string>::ok(out.str());
    }
    const auto group = [&](const char* label, const std::vector<std::string>& items, std::string_view color) {
        out << "  " << colorize(label, color, options) << " (" << items.size() << ")";
        out << "\n";
        for (const std::string& item : items) {
            out << "    " << item << "\n";
        }
    };
    out << colorize("Function diff", ansi_bold, options) << "\n";
    group("added", result.added, ansi_green);
    group("removed", result.removed, ansi_red);
    group("changed", result.changed, ansi_yellow);
    out << "  unchanged: " << result.unchanged << "\n";
    return Result<std::string>::ok(out.str());
}

} // namespace roe::format
