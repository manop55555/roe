// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
#include "roe/resolver.hpp"

#if defined(__GNUG__)
#include <cxxabi.h>
#endif

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace roe::resolver {
namespace {

bool contains(std::string_view text, std::string_view needle) noexcept {
    return text.find(needle) != std::string_view::npos;
}

bool include_symbol(const elf::Symbol& symbol, const Options& options) noexcept {
    if (symbol.name.empty() || !symbol.defined) {
        return false;
    }
    if (symbol.type == elf::SymbolType::File || symbol.type == elf::SymbolType::Section) {
        return false;
    }
    // Skip compiler-internal local labels (.L*) and mapping symbols ($a/$t/$d/$x),
    // which would otherwise pollute listings and branch annotations on .o files.
    if (symbol.name.rfind(".L", 0) == 0) {
        return false;
    }
    if (symbol.name.front() == '$') {
        return false;
    }
    if (symbol.dynamic && !options.include_dynamic_symbols) {
        return false;
    }
    if (symbol.bind == elf::SymbolBind::Local && !options.include_local_symbols) {
        return false;
    }
    return true;
}

bool is_metadata_relocation_section(std::string_view section_name) noexcept {
    return contains(section_name, ".debug") || contains(section_name, ".eh_frame") ||
           contains(section_name, ".comment") || contains(section_name, ".note");
}

std::optional<elf::Section> find_plt_section(const elf::File& file) {
    const auto found = std::find_if(
        file.sections.begin(),
        file.sections.end(),
        [](const elf::Section& section) { return section.name == ".plt"; });
    if (found == file.sections.end()) {
        return std::nullopt;
    }
    return *found;
}

bool is_plt_relocation_section(std::string_view section_name) noexcept {
    return contains(section_name, ".rela.plt") || contains(section_name, ".rel.plt");
}

std::string display_name(std::string_view raw_name, const Options& options) {
    if (raw_name.empty()) {
        return {};
    }
    if (options.demangle_names) {
        return demangle(raw_name);
    }
    return std::string(raw_name);
}

std::string relocation_raw_name(const elf::File& file, const elf::Relocation& relocation) {
    if (!relocation.symbol_name.empty()) {
        return relocation.symbol_name;
    }

    const auto symbol_count = static_cast<std::uint64_t>(file.symbols.size());
    if (relocation.symbol_index < symbol_count) {
        return file.symbols[static_cast<std::size_t>(relocation.symbol_index)].name;
    }

    return {};
}

std::string relocation_display_name(
    std::string_view raw_name,
    const elf::Relocation& relocation,
    const Options& options) {
    std::string name = display_name(raw_name, options);
    if (name.empty()) {
        name = relocation.section_name.empty() ? std::string{"<relocation>"} : relocation.section_name;
    }

    if (contains(relocation.section_name, ".plt") && !contains(name, "@plt")) {
        name += "@plt";
    } else if (contains(relocation.section_name, ".got") && !contains(name, "@got")) {
        name += "@got";
    }

    return name;
}

std::uint64_t symbol_end(const ResolvedSymbol& symbol) noexcept {
    if (symbol.size == 0) {
        return symbol.address;
    }
    const std::uint64_t max_tail = std::numeric_limits<std::uint64_t>::max() - symbol.address;
    if (symbol.size > max_tail) {
        return std::numeric_limits<std::uint64_t>::max();
    }
    return symbol.address + symbol.size;
}

std::optional<ResolvedReference> relocation_in_instruction(
    const Index& index,
    const disasm::Instruction& instruction) {
    if (const auto exact = relocation_at(index, instruction.address)) {
        return exact;
    }

    if (instruction.size == 0) {
        return std::nullopt;
    }

    const std::uint64_t max_tail =
        std::numeric_limits<std::uint64_t>::max() - instruction.address;
    const std::uint64_t width = instruction.size > max_tail ? max_tail : instruction.size;
    const std::uint64_t end = instruction.address + width;

    const auto first = std::lower_bound(
        index.relocations.begin(),
        index.relocations.end(),
        instruction.address,
        [](const ResolvedReference& reference, std::uint64_t address) {
            return reference.address < address;
        });

    if (first != index.relocations.end() && first->address < end) {
        return *first;
    }

    return std::nullopt;
}

} // namespace

Result<Index> build_index(const elf::File& file, const Options& options) {
    Index index;
    index.symbols.reserve(file.symbols.size());
    index.relocations.reserve(file.relocations.size());
    std::vector<std::string> plt_relocation_names;

    for (const elf::Symbol& symbol : file.symbols) {
        if (!include_symbol(symbol, options)) {
            continue;
        }

        index.symbols.push_back(ResolvedSymbol{
            display_name(symbol.name, options),
            symbol.name,
            symbol.address,
            symbol.size,
            false,
            symbol.dynamic,
        });
    }

    for (const elf::Relocation& relocation : file.relocations) {
        if (is_metadata_relocation_section(relocation.section_name)) {
            continue;
        }

        const std::string raw_name = relocation_raw_name(file, relocation);
        // Relocations to compiler-internal local labels (.L*) are redundant with the
        // branch targets roe already resolves; suppress them to keep output clean.
        if (raw_name.rfind(".L", 0) == 0) {
            continue;
        }
        if (is_plt_relocation_section(relocation.section_name) && !raw_name.empty()) {
            plt_relocation_names.push_back(raw_name);
        }
        index.relocations.push_back(ResolvedReference{
            relocation.offset,
            relocation_display_name(raw_name, relocation, options),
            raw_name,
            relocation.section_name,
            relocation.type,
            relocation.addend,
            relocation.has_addend,
        });
    }

    const std::optional<elf::Section> plt_section = find_plt_section(file);
    if (plt_section.has_value() && plt_section->address != 0U) {
        constexpr std::uint64_t x86_64_plt_entry_size = 16U;
        std::uint64_t slot = 1U;
        for (const std::string& raw_name : plt_relocation_names) {
            const std::uint64_t address = plt_section->address + (slot * x86_64_plt_entry_size);
            std::string name = display_name(raw_name, options);
            if (!contains(name, "@plt")) {
                name += "@plt";
            }
            index.symbols.push_back(ResolvedSymbol{
                std::move(name),
                raw_name,
                address,
                x86_64_plt_entry_size,
                false,
                true,
            });
            ++slot;
        }
    }

    std::sort(
        index.symbols.begin(),
        index.symbols.end(),
        [](const ResolvedSymbol& lhs, const ResolvedSymbol& rhs) {
            if (lhs.address != rhs.address) {
                return lhs.address < rhs.address;
            }
            return lhs.raw_name < rhs.raw_name;
        });

    std::sort(
        index.relocations.begin(),
        index.relocations.end(),
        [](const ResolvedReference& lhs, const ResolvedReference& rhs) {
            if (lhs.address != rhs.address) {
                return lhs.address < rhs.address;
            }
            if (lhs.relocation_section != rhs.relocation_section) {
                return lhs.relocation_section < rhs.relocation_section;
            }
            return lhs.raw_name < rhs.raw_name;
        });

    return Result<Index>::ok(std::move(index));
}

namespace {

bool include_binary_symbol(const binary::Symbol& symbol, const Options& options) noexcept {
    if (symbol.name.empty() || !symbol.defined) {
        return false;
    }
    if (symbol.type == binary::SymbolType::File || symbol.type == binary::SymbolType::Section) {
        return false;
    }
    if (symbol.name.rfind(".L", 0) == 0 || symbol.name.front() == '$') {
        return false;
    }
    if (symbol.dynamic && !options.include_dynamic_symbols) {
        return false;
    }
    if (symbol.bind == binary::SymbolBind::Local && !options.include_local_symbols) {
        return false;
    }
    return true;
}

std::string relocation_display_for(std::string_view raw_name, std::string_view section_name, const Options& options) {
    std::string name = display_name(raw_name, options);
    if (name.empty()) {
        name = section_name.empty() ? std::string{"<relocation>"} : std::string(section_name);
    }
    if (contains(section_name, ".plt") && !contains(name, "@plt")) {
        name += "@plt";
    } else if (contains(section_name, ".got") && !contains(name, "@got")) {
        name += "@got";
    }
    return name;
}

} // namespace

Result<Index> build_index(const binary::BinaryFile& file, const Options& options) {
    const std::optional<binary::Object> object = binary::primary_object(file.view());
    if (!object.has_value()) {
        return Result<Index>::err({ErrorCode::NotFound, "binary contains no analyzable object"});
    }

    Index index;
    index.format = object->format;
    index.strings = object->strings;
    index.symbols.reserve(object->symbols.size());
    index.relocations.reserve(object->relocations.size());
    std::vector<std::string> plt_relocation_names;

    for (const binary::Symbol& symbol : object->symbols) {
        if (!include_binary_symbol(symbol, options)) {
            continue;
        }
        index.symbols.push_back(ResolvedSymbol{
            display_name(symbol.raw_name, options),
            symbol.raw_name,
            symbol.address,
            symbol.size,
            false,
            symbol.dynamic,
            symbol.object_index,
            false,
        });
    }

    for (const binary::Relocation& relocation : object->relocations) {
        if (is_metadata_relocation_section(relocation.section_name)) {
            continue;
        }
        const std::string raw_name =
            relocation.symbol_name.empty() ? relocation.raw_symbol_name : relocation.symbol_name;
        if (raw_name.rfind(".L", 0) == 0) {
            continue;
        }
        if (is_plt_relocation_section(relocation.section_name) && !raw_name.empty()) {
            plt_relocation_names.push_back(raw_name);
        }
        index.relocations.push_back(ResolvedReference{
            relocation.offset,
            relocation_display_for(raw_name, relocation.section_name, options),
            raw_name,
            relocation.section_name,
            relocation.type,
            relocation.addend,
            relocation.has_addend,
            relocation.object_index,
        });
    }

    const auto plt_section = std::find_if(
        object->sections.begin(), object->sections.end(),
        [](const binary::Section& section) { return section.name == ".plt"; });
    if (plt_section != object->sections.end() && plt_section->address != 0U) {
        constexpr std::uint64_t plt_entry_size = 16U;
        std::uint64_t slot = 1U;
        for (const std::string& raw_name : plt_relocation_names) {
            const std::uint64_t address = plt_section->address + (slot * plt_entry_size);
            std::string name = display_name(raw_name, options);
            if (!contains(name, "@plt")) {
                name += "@plt";
            }
            index.symbols.push_back(ResolvedSymbol{
                std::move(name), raw_name, address, plt_entry_size, false, true, object->index, true});
            ++slot;
        }
    }

    std::sort(index.symbols.begin(), index.symbols.end(),
        [](const ResolvedSymbol& lhs, const ResolvedSymbol& rhs) {
            if (lhs.address != rhs.address) {
                return lhs.address < rhs.address;
            }
            return lhs.raw_name < rhs.raw_name;
        });
    std::sort(index.relocations.begin(), index.relocations.end(),
        [](const ResolvedReference& lhs, const ResolvedReference& rhs) {
            if (lhs.address != rhs.address) {
                return lhs.address < rhs.address;
            }
            if (lhs.relocation_section != rhs.relocation_section) {
                return lhs.relocation_section < rhs.relocation_section;
            }
            return lhs.raw_name < rhs.raw_name;
        });

    return Result<Index>::ok(std::move(index));
}

std::optional<ResolvedSymbol> symbol_at(const Index& index, std::uint64_t address) {
    const auto it = std::lower_bound(
        index.symbols.begin(),
        index.symbols.end(),
        address,
        [](const ResolvedSymbol& symbol, std::uint64_t lookup_address) {
            return symbol.address < lookup_address;
        });

    if (it == index.symbols.end() || it->address != address) {
        return std::nullopt;
    }

    ResolvedSymbol result = *it;
    result.exact = true;
    return result;
}

std::optional<ResolvedSymbol> nearest_symbol(const Index& index, std::uint64_t address) {
    if (index.symbols.empty()) {
        return std::nullopt;
    }

    const auto upper = std::upper_bound(
        index.symbols.begin(),
        index.symbols.end(),
        address,
        [](std::uint64_t lookup_address, const ResolvedSymbol& symbol) {
            return lookup_address < symbol.address;
        });

    if (upper == index.symbols.begin()) {
        return std::nullopt;
    }

    auto best = upper;
    --best;

    ResolvedSymbol result = *best;
    result.exact = result.address == address;

    if (result.size == 0 || address < symbol_end(result)) {
        return result;
    }

    return result;
}

std::optional<ResolvedReference> relocation_at(const Index& index, std::uint64_t address) {
    const auto it = std::lower_bound(
        index.relocations.begin(),
        index.relocations.end(),
        address,
        [](const ResolvedReference& reference, std::uint64_t lookup_address) {
            return reference.address < lookup_address;
        });

    if (it == index.relocations.end() || it->address != address) {
        return std::nullopt;
    }

    return *it;
}

std::vector<AnnotatedInstruction> annotate(
    const Index& index,
    const std::vector<disasm::Instruction>& instructions) {
    std::vector<AnnotatedInstruction> annotated;
    annotated.reserve(instructions.size());

    for (const disasm::Instruction& instruction : instructions) {
        annotated.push_back(AnnotatedInstruction{
            instruction,
            nearest_symbol(index, instruction.address),
            relocation_in_instruction(index, instruction),
            instruction.branch_target.has_value() ? symbol_at(index, instruction.branch_target.value()) : std::nullopt,
            std::nullopt,
            std::nullopt,
            0U,
            std::string{},
        });
    }

    return annotated;
}

namespace {

// Strip the trailing Rust legacy hash component (::h<>=16 hex digits) that the
// Itanium demangler leaves on _ZN..17h..E names.
std::string strip_rust_legacy_hash(std::string name) {
    const auto pos = name.rfind("::h");
    if (pos == std::string::npos || pos + 3U >= name.size()) {
        return name;
    }
    for (std::size_t i = pos + 3U; i < name.size(); ++i) {
        const char character = name[i];
        const bool hex = (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f');
        if (!hex) {
            return name;
        }
    }
    if (name.size() - (pos + 3U) >= 16U) {
        return name.substr(0, pos);
    }
    return name;
}

// Minimal Rust v0 (RFC 2603) demangler covering the common path/identifier/type
// grammar with backreferences. Returns nullopt on constructs it does not model
// (so the caller falls back to the raw name); a global step/depth budget bounds
// work on adversarial input.
class RustV0Demangler {
public:
    explicit RustV0Demangler(std::string_view body) : body_(body) {}

    std::optional<std::string> run() {
        skip_optional_decimal();
        std::string out;
        if (!parse_path(out, pos_) || failed_) {
            return std::nullopt;
        }
        return out;
    }

private:
    std::string_view body_;
    std::size_t pos_{0};
    bool failed_{false};
    int steps_{0};
    int depth_{0};

    bool budget() noexcept {
        if (++steps_ > 20000 || depth_ > 256) {
            failed_ = true;
            return false;
        }
        return true;
    }
    char peek(std::size_t position) const noexcept { return position < body_.size() ? body_[position] : '\0'; }

    void skip_optional_decimal() noexcept {
        if (peek(pos_) >= '1' && peek(pos_) <= '9') {
            while (peek(pos_) >= '0' && peek(pos_) <= '9') {
                ++pos_;
            }
        }
    }

    bool parse_base62(std::size_t& position, std::uint64_t& value) {
        if (peek(position) == '_') {
            ++position;
            value = 0;
            return true;
        }
        std::uint64_t accumulated = 0;
        bool any = false;
        while (position < body_.size()) {
            const char character = body_[position];
            std::uint64_t digit = 0;
            if (character >= '0' && character <= '9') {
                digit = static_cast<std::uint64_t>(character - '0');
            } else if (character >= 'a' && character <= 'z') {
                digit = 10U + static_cast<std::uint64_t>(character - 'a');
            } else if (character >= 'A' && character <= 'Z') {
                digit = 36U + static_cast<std::uint64_t>(character - 'A');
            } else {
                break;
            }
            accumulated = accumulated * 62U + digit;
            ++position;
            any = true;
        }
        if (peek(position) != '_') {
            failed_ = true;
            return false;
        }
        ++position;
        value = any ? accumulated + 1U : 0U;
        return true;
    }

    bool parse_decimal(std::size_t& position, std::uint64_t& value) noexcept {
        value = 0;
        bool any = false;
        while (position < body_.size() && body_[position] >= '0' && body_[position] <= '9') {
            value = value * 10U + static_cast<std::uint64_t>(body_[position] - '0');
            ++position;
            any = true;
        }
        return any;
    }

    bool parse_identifier(std::string& out, std::size_t& position) {
        if (!budget()) {
            return false;
        }
        if (peek(position) == 's') {
            ++position;
            std::uint64_t disambiguator = 0;
            if (!parse_base62(position, disambiguator)) {
                return false;
            }
        }
        if (peek(position) == 'u') {
            ++position;
        }
        std::uint64_t length = 0;
        if (!parse_decimal(position, length)) {
            failed_ = true;
            return false;
        }
        if (peek(position) == '_') {
            ++position;
        }
        if (position + length > body_.size()) {
            failed_ = true;
            return false;
        }
        out += std::string(body_.substr(position, static_cast<std::size_t>(length)));
        position += static_cast<std::size_t>(length);
        return true;
    }

    bool parse_path(std::string& out, std::size_t& position) {
        if (!budget()) {
            return false;
        }
        ++depth_;
        const bool ok = parse_path_inner(out, position);
        --depth_;
        return ok;
    }

    bool parse_path_inner(std::string& out, std::size_t& position) {
        switch (peek(position)) {
        case 'C':
            ++position;
            return parse_identifier(out, position);
        case 'N': {
            ++position;
            ++position; // namespace discriminator letter
            std::string parent;
            if (!parse_path(parent, position)) {
                return false;
            }
            std::string ident;
            if (!parse_identifier(ident, position)) {
                return false;
            }
            out += parent;
            if (!ident.empty()) {
                out += "::";
                out += ident;
            }
            return true;
        }
        case 'I': {
            ++position;
            std::string base;
            if (!parse_path(base, position)) {
                return false;
            }
            out += base;
            out += "::<";
            bool first = true;
            while (peek(position) != 'E' && position < body_.size()) {
                if (!budget()) {
                    return false;
                }
                if (!first) {
                    out += ", ";
                }
                first = false;
                if (!parse_generic_arg(out, position)) {
                    return false;
                }
            }
            if (peek(position) != 'E') {
                failed_ = true;
                return false;
            }
            ++position;
            out += ">";
            return true;
        }
        case 'B': {
            ++position;
            std::uint64_t offset = 0;
            if (!parse_base62(position, offset)) {
                return false;
            }
            if (offset >= body_.size()) {
                failed_ = true;
                return false;
            }
            std::size_t target = static_cast<std::size_t>(offset);
            return parse_path(out, target);
        }
        case 'M': {
            ++position;
            std::string impl_path;
            if (!parse_path(impl_path, position)) {
                return false;
            }
            std::string type;
            if (!parse_type(type, position)) {
                return false;
            }
            out += "<" + type + ">";
            return true;
        }
        case 'X':
        case 'Y': {
            const bool has_impl_path = peek(position) == 'X';
            ++position;
            if (has_impl_path) {
                std::string impl_path;
                if (!parse_path(impl_path, position)) {
                    return false;
                }
            }
            std::string type;
            if (!parse_type(type, position)) {
                return false;
            }
            std::string trait;
            if (!parse_path(trait, position)) {
                return false;
            }
            out += "<" + type + " as " + trait + ">";
            return true;
        }
        default:
            failed_ = true;
            return false;
        }
    }

    bool parse_generic_arg(std::string& out, std::size_t& position) {
        if (peek(position) == 'L') {
            ++position;
            std::uint64_t lifetime = 0;
            if (!parse_base62(position, lifetime)) {
                return false;
            }
            out += "'_";
            return true;
        }
        if (peek(position) == 'K') {
            ++position;
            return parse_const(out, position);
        }
        return parse_type(out, position);
    }

    bool parse_const(std::string& out, std::size_t& position) {
        if (peek(position) == 'p') {
            ++position;
            out += "_";
            return true;
        }
        std::string type;
        if (!parse_type(type, position)) {
            return false;
        }
        if (peek(position) == 'n') {
            ++position;
        }
        std::string digits;
        while (position < body_.size() && body_[position] != '_') {
            digits += body_[position];
            ++position;
        }
        if (peek(position) == '_') {
            ++position;
        }
        out += digits.empty() ? std::string("_") : digits;
        return true;
    }

    bool parse_type(std::string& out, std::size_t& position) {
        if (!budget()) {
            return false;
        }
        ++depth_;
        const bool ok = parse_type_inner(out, position);
        --depth_;
        return ok;
    }

    bool parse_type_inner(std::string& out, std::size_t& position) {
        const char tag = peek(position);
        const char* basic = nullptr;
        switch (tag) {
        case 'a': basic = "i8"; break;
        case 'b': basic = "bool"; break;
        case 'c': basic = "char"; break;
        case 'd': basic = "f64"; break;
        case 'e': basic = "str"; break;
        case 'f': basic = "f32"; break;
        case 'h': basic = "u8"; break;
        case 'i': basic = "isize"; break;
        case 'j': basic = "usize"; break;
        case 'l': basic = "i32"; break;
        case 'm': basic = "u32"; break;
        case 'n': basic = "i128"; break;
        case 'o': basic = "u128"; break;
        case 's': basic = "i16"; break;
        case 't': basic = "u16"; break;
        case 'u': basic = "()"; break;
        case 'x': basic = "i64"; break;
        case 'y': basic = "u64"; break;
        case 'z': basic = "!"; break;
        case 'p': basic = "_"; break;
        default: break;
        }
        if (basic != nullptr) {
            ++position;
            out += basic;
            return true;
        }
        switch (tag) {
        case 'A': {
            ++position;
            std::string element;
            if (!parse_type(element, position)) {
                return false;
            }
            std::string length;
            if (!parse_const(length, position)) {
                return false;
            }
            out += "[" + element + "; " + length + "]";
            return true;
        }
        case 'S': {
            ++position;
            std::string element;
            if (!parse_type(element, position)) {
                return false;
            }
            out += "[" + element + "]";
            return true;
        }
        case 'R':
        case 'Q': {
            const bool mutable_ref = tag == 'Q';
            ++position;
            if (peek(position) == 'L') {
                ++position;
                std::uint64_t lifetime = 0;
                if (!parse_base62(position, lifetime)) {
                    return false;
                }
            }
            std::string pointee;
            if (!parse_type(pointee, position)) {
                return false;
            }
            out += mutable_ref ? "&mut " + pointee : "&" + pointee;
            return true;
        }
        case 'P':
        case 'O': {
            const bool mutable_ptr = tag == 'O';
            ++position;
            std::string pointee;
            if (!parse_type(pointee, position)) {
                return false;
            }
            out += mutable_ptr ? "*mut " + pointee : "*const " + pointee;
            return true;
        }
        case 'T': {
            ++position;
            out += "(";
            bool first = true;
            while (peek(position) != 'E' && position < body_.size()) {
                if (!budget()) {
                    return false;
                }
                if (!first) {
                    out += ", ";
                }
                first = false;
                std::string element;
                if (!parse_type(element, position)) {
                    return false;
                }
                out += element;
            }
            if (peek(position) != 'E') {
                failed_ = true;
                return false;
            }
            ++position;
            out += ")";
            return true;
        }
        case 'B': {
            ++position;
            std::uint64_t offset = 0;
            if (!parse_base62(position, offset)) {
                return false;
            }
            if (offset >= body_.size()) {
                failed_ = true;
                return false;
            }
            std::size_t target = static_cast<std::size_t>(offset);
            return parse_type(out, target);
        }
        case 'C':
        case 'N':
        case 'I':
        case 'M':
        case 'X':
        case 'Y':
            return parse_path(out, position);
        default:
            failed_ = true;
            return false;
        }
    }
};

std::optional<std::string> demangle_rust_v0(std::string_view name) {
    if (name.size() < 3U || name[0] != '_' || name[1] != 'R') {
        return std::nullopt;
    }
    RustV0Demangler demangler(name.substr(2));
    return demangler.run();
}

} // namespace

std::string demangle(std::string_view name) {
    if (name.size() >= 2U && name[0] == '_' && name[1] == 'R') {
        if (const std::optional<std::string> rust = demangle_rust_v0(name)) {
            return *rust;
        }
        return std::string(name);
    }

#if defined(__GNUG__)
    int status = 0;
    using DemanglePtr = std::unique_ptr<char, decltype(&std::free)>;
    DemanglePtr demangled{
        abi::__cxa_demangle(std::string(name).c_str(), nullptr, nullptr, &status),
        &std::free,
    };

    if (status == 0 && demangled) {
        return strip_rust_legacy_hash(std::string(demangled.get()));
    }
#endif

    return std::string(name);
}

} // namespace roe::resolver
