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
    std::ostringstream out;
    out << program_name << " " << version_string << "\n";
    out << "Readable object explorer\n";
    return Result<std::string>::ok(out.str());
}

Result<std::string> render_help()
{
    std::ostringstream out;
    out << "roe " << version_string << "\n";
    out << "Usage:\n";
    out << "  roe <file>\n";
    out << "  roe <file> <symbol> [--no-color] [--json]\n";
    out << "  roe <file> --section <name> [--no-color] [--json]\n";
    out << "  roe --help\n";
    out << "  roe --version\n\n";
    out << "Commands:\n";
    out << "  <file>                 List functions with preserved addresses\n";
    out << "  <file> <symbol>        Disassemble one function\n";
    out << "  --section <name>       Disassemble an entire section, for example .text\n\n";
    out << "Options:\n";
    out << "  --json                 Emit machine-readable JSON\n";
    out << "  --no-color             Disable ANSI color for pipes and logs\n";
    out << "  --help                 Show this help text\n";
    out << "  --version              Show version banner\n";
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
    out << colorize("Functions", ansi_bold, options) << " in " << file.source_name << "\n";
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
            if (symbol.dynamic) {
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
        if (function.dynamic) {
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

    for (const resolver::AnnotatedInstruction& annotated : instructions) {
        const disasm::Instruction& instruction = annotated.instruction;
        const auto label = labels.find(instruction.address);
        if (label != labels.end()) {
            out << colorize(label->second, ansi_yellow, options) << ":\n";
        }

        out << colorize(padded_hex_address(instruction.address), ansi_dim, options) << ": ";
        const std::string bytes = bytes_text(instruction.bytes);
        if (!bytes.empty()) {
            out << std::left << std::setw(23) << bytes << std::right;
        } else {
            out << std::left << std::setw(23) << "" << std::right;
        }

        out << colorize(instruction.mnemonic, ansi_green, options);
        if (!instruction.operands.empty()) {
            out << ' ' << instruction.operands;
        }

        if (instruction.branch_target.has_value()) {
            const std::uint64_t target = instruction.branch_target.value();
            const std::string target_text = hex_address(target);
            if (instruction.operands.find(target_text) == std::string::npos) {
                out << ' ' << target_text;
            }
            const std::optional<std::string> preview = preview_for_target(instructions, labels, target);
            if (preview.has_value()) {
                out << " \u2192 [" << preview.value() << "]";
            }
        }

        if (annotated.reference.has_value()) {
            out << "  " << colorize("; ref ", ansi_cyan, options) << annotated.reference->name;
            out << " @" << hex_address(annotated.reference->address);
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

} // namespace roe::format
