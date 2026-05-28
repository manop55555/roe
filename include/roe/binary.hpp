// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
#pragma once

/**
 * @file binary.hpp
 * @brief Format-neutral binary object model used by v1 roe workflows.
 */

#include "roe/core.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace roe::binary {

/**
 * @brief Container format detected from magic bytes.
 */
enum class Format : std::uint8_t {
    Unknown,
    Elf,
    MachO,
    MachOFat,
    PeCoff,
    Archive
};

/**
 * @brief Normalized CPU architecture.
 */
enum class Architecture : std::uint8_t {
    Unknown,
    X86,
    X86_64,
    Arm,
    ArmThumb,
    AArch64,
    RiscV32,
    RiscV64,
    Mips32,
    Mips32el,
    Mips64,
    Mips64el,
    PowerPc32,
    PowerPc64,
    PowerPc64le
};

enum class AddressWidth : std::uint8_t { Bits32, Bits64 };
enum class Endianness : std::uint8_t { Little, Big };
enum class ObjectKind : std::uint8_t { Unknown, Relocatable, Executable, SharedLibrary, StaticArchive, Object };
enum class SectionKind : std::uint8_t { Unknown, Code, Data, ReadOnlyData, CString, Debug, Relocation, SymbolTable };
enum class SymbolBind : std::uint8_t { Local, Global, Weak, Imported, Exported, Other };
enum class SymbolType : std::uint8_t { Unknown, NoType, Object, Function, Section, File, Tls };
enum class RelocationEncoding : std::uint8_t { Rel, Rela, Coff, MachO };

/**
 * @brief Section metadata normalized across object formats.
 */
struct Section {
    std::string name;
    std::size_t object_index{0};
    std::uint32_t index{0};
    SectionKind kind{SectionKind::Unknown};
    std::uint64_t address{0};
    std::uint64_t offset{0};
    std::uint64_t size{0};
    std::uint64_t alignment{0};
    bool readable{false};
    bool writable{false};
    bool executable{false};
    bool contains_strings{false};
};

/**
 * @brief A loadable region: ELF program header, Mach-O segment/load command, or
 *        PE data directory. Normalized so --segments is one code path.
 */
struct Segment {
    std::string name;
    std::uint64_t address{0};
    std::uint64_t offset{0};
    std::uint64_t size{0};
    bool readable{false};
    bool writable{false};
    bool executable{false};
    std::string detail;
};

/**
 * @brief Symbol metadata normalized across static and dynamic symbol tables.
 */
struct Symbol {
    std::string name;
    std::string raw_name;
    std::size_t object_index{0};
    std::uint64_t address{0};
    std::uint64_t size{0};
    std::uint32_t section_index{0};
    SymbolBind bind{SymbolBind::Other};
    SymbolType type{SymbolType::Unknown};
    bool defined{false};
    bool dynamic{false};
    bool synthetic{false};
    std::string library; ///< Owning library for an import/export, when known (Mach-O dylib, PE DLL).
};

/**
 * @brief Relocation/reference metadata normalized across supported formats.
 */
struct Relocation {
    std::string section_name;
    std::size_t object_index{0};
    std::uint64_t offset{0};
    std::uint64_t target_address{0};
    std::uint64_t symbol_index{0};
    std::string symbol_name;
    std::string raw_symbol_name;
    std::uint32_t type{0};
    std::int64_t addend{0};
    bool has_addend{false};
    RelocationEncoding encoding{RelocationEncoding::Rel};
};

/**
 * @brief String literal discovered in a read-only string section.
 */
struct StringLiteral {
    std::size_t object_index{0};
    std::uint64_t address{0};
    std::uint64_t size{0};
    std::string value;
};

/**
 * @brief One architecture slice or archive member inside a parsed file.
 */
struct Object {
    std::string name;
    std::size_t index{0};
    Format format{Format::Unknown};
    Architecture architecture{Architecture::Unknown};
    AddressWidth address_width{AddressWidth::Bits64};
    Endianness endianness{Endianness::Little};
    ObjectKind kind{ObjectKind::Unknown};
    std::uint64_t entry{0};
    std::vector<Section> sections;
    std::vector<Segment> segments;
    std::vector<Symbol> symbols;
    std::vector<Relocation> relocations;
    std::vector<StringLiteral> strings;
    std::vector<std::string> libraries; ///< Linked/needed libraries (ELF DT_NEEDED, Mach-O dylibs, PE import DLLs).
    bool stripped{false};
};

/**
 * @brief Owned bytes for a section.
 */
struct SectionBytes {
    std::size_t object_index{0};
    std::string section_name;
    std::uint64_t address{0};
    std::vector<std::uint8_t> bytes;
};

/**
 * @brief Complete normalized view for one input path.
 */
struct FileView {
    std::string source_name;
    Format format{Format::Unknown};
    std::vector<std::uint8_t> first_bytes;
    std::vector<Object> objects;
};

/**
 * @brief Polymorphic adapter implemented by each parser backend.
 */
class BinaryFile {
public:
    virtual ~BinaryFile() = default;

    /**
     * @brief Return the normalized metadata view for this file.
     */
    [[nodiscard]] virtual const FileView& view() const noexcept = 0;

    /**
     * @brief Return owned section bytes for a normalized section.
     */
    [[nodiscard]] virtual Result<SectionBytes> section_bytes(const Section& section) const = 0;
};

/**
 * @brief Detect format from magic bytes only.
 */
Format detect_format(const std::vector<std::uint8_t>& bytes) noexcept;

/**
 * @brief Load and parse any supported format from disk.
 */
Result<std::unique_ptr<BinaryFile>> load_file(const std::filesystem::path& path);

/**
 * @brief Parse any supported format from owned bytes.
 */
Result<std::unique_ptr<BinaryFile>> load_bytes(std::string source_name, std::vector<std::uint8_t> bytes);

/**
 * @brief Return the preferred object for workflows that omit an architecture selector.
 */
std::optional<Object> primary_object(const FileView& file);

/**
 * @brief Find a section by object and exact section name.
 */
std::optional<Section> find_section(const FileView& file, std::size_t object_index, std::string_view name);

/**
 * @brief Return all function symbols in the selected object.
 */
std::vector<Symbol> function_symbols(const FileView& file, std::size_t object_index);

/**
 * @brief Find a symbol by exact raw or demangled name in the selected object.
 */
std::optional<Symbol> find_symbol(const FileView& file, std::size_t object_index, std::string_view name);

/**
 * @brief Human-readable name for a normalized format enum.
 */
std::string_view format_name(Format format) noexcept;

/**
 * @brief Human-readable name for a normalized architecture enum.
 */
std::string_view architecture_name(Architecture architecture) noexcept;

/**
 * @brief Render first bytes for unknown-format diagnostics.
 */
std::string first_bytes_hex(const std::vector<std::uint8_t>& bytes, std::size_t limit = 16);

} // namespace roe::binary
