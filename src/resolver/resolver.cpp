#include "roe/resolver.hpp"

#if defined(__GNUG__)
#include <cxxabi.h>
#endif

#include <algorithm>
#include <cstdlib>
#include <limits>
#include <memory>
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
        });
    }

    return annotated;
}

std::string demangle(std::string_view name) {
#if defined(__GNUG__)
    int status = 0;
    using DemanglePtr = std::unique_ptr<char, decltype(&std::free)>;
    DemanglePtr demangled{
        abi::__cxa_demangle(std::string(name).c_str(), nullptr, nullptr, &status),
        &std::free,
    };

    if (status == 0 && demangled) {
        return std::string(demangled.get());
    }
#endif

    return std::string(name);
}

} // namespace roe::resolver
