#pragma once

/**
 * @file elf.hpp
 * @brief Public ELF parser model and entry points.
 */

#include "roe/core.hpp"
#include "roe/binary.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace roe::elf {

enum class Class : std::uint8_t { Elf32, Elf64 };
enum class Endianness : std::uint8_t { Little, Big };
enum class FileType : std::uint16_t { None, Relocatable, Executable, SharedObject, Core, Other };
enum class Machine : std::uint16_t {
    Unknown,
    X86,
    X86_64,
    Arm,
    AArch64,
    RiscV,
    Mips,
    PowerPc,
    PowerPc64,
    Other
};
enum class SymbolBind : std::uint8_t { Local, Global, Weak, Other };
enum class SymbolType : std::uint8_t { NoType, Object, Function, Section, File, Common, Tls, Other };

/**
 * @brief ELF section metadata.
 */
struct Section {
    std::string name;
    std::uint16_t index{0};
    std::uint32_t type{0};
    std::uint64_t flags{0};
    std::uint64_t address{0};
    std::uint64_t offset{0};
    std::uint64_t size{0};
    std::uint64_t alignment{0};
    bool executable{false};
};

/**
 * @brief ELF loadable or metadata segment.
 */
struct Segment {
    std::uint32_t type{0};
    std::uint32_t flags{0};
    std::uint64_t virtual_address{0};
    std::uint64_t physical_address{0};
    std::uint64_t offset{0};
    std::uint64_t file_size{0};
    std::uint64_t memory_size{0};
    std::uint64_t alignment{0};
};

/**
 * @brief ELF symbol table entry normalized across ELF32 and ELF64.
 */
struct Symbol {
    std::string name;
    std::uint64_t address{0};
    std::uint64_t size{0};
    std::uint16_t section_index{0};
    SymbolBind bind{SymbolBind::Other};
    SymbolType type{SymbolType::Other};
    bool defined{false};
    bool dynamic{false};
};

/**
 * @brief ELF relocation entry normalized across REL and RELA formats.
 */
struct Relocation {
    std::string section_name;
    std::uint64_t offset{0};
    std::uint32_t type{0};
    std::uint64_t symbol_index{0};
    std::string symbol_name;
    std::int64_t addend{0};
    bool has_addend{false};
};

/**
 * @brief Borrowed bytes for a section. Valid while the owning File is alive.
 */
struct SectionBytes {
    std::uint64_t address{0};
    std::vector<std::uint8_t>::const_iterator begin;
    std::vector<std::uint8_t>::const_iterator end;
};

/**
 * @brief Parsed ELF file model.
 */
struct File {
    std::string source_name;
    std::vector<std::uint8_t> image;
    Class elf_class{Class::Elf64};
    Endianness endianness{Endianness::Little};
    FileType file_type{FileType::Other};
    Machine machine{Machine::Unknown};
    std::uint64_t entry{0};
    std::vector<Section> sections;
    std::vector<Segment> segments;
    std::vector<Symbol> symbols;
    std::vector<Relocation> relocations;
    bool stripped{false};
};

/**
 * @brief Parse an ELF file from disk.
 */
Result<File> parse_file(const std::filesystem::path& path);

/**
 * @brief Parse an ELF file from owned bytes.
 */
Result<File> parse_bytes(std::string source_name, std::vector<std::uint8_t> bytes);

/**
 * @brief Create the format-neutral BinaryFile adapter for a parsed ELF file.
 */
Result<std::unique_ptr<binary::BinaryFile>> open_file(const std::filesystem::path& path);

/**
 * @brief Create the format-neutral BinaryFile adapter from owned ELF bytes.
 */
Result<std::unique_ptr<binary::BinaryFile>> open_bytes(std::string source_name, std::vector<std::uint8_t> bytes);

/**
 * @brief Find a section by exact name.
 */
std::optional<Section> find_section(const File& file, std::string_view name);

/**
 * @brief Return all symbols classified as functions.
 */
std::vector<Symbol> function_symbols(const File& file);

/**
 * @brief Find a symbol by exact raw or demangled name.
 */
std::optional<Symbol> find_symbol(const File& file, std::string_view name);

/**
 * @brief Return borrowed section bytes for a parsed section.
 */
std::optional<SectionBytes> section_bytes(const File& file, const Section& section);

} // namespace roe::elf
