// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The roe Authors

#include "roe/binary.hpp"

#include "roe/elf.hpp"
#include "roe/macho.hpp"
#include "roe/pe.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <sstream>

namespace roe::binary {
namespace {

Error make_error(ErrorCode code, std::string message)
{
    return Error{code, std::move(message), 0, false};
}

std::uint32_t read_be32(const std::vector<std::uint8_t>& bytes) noexcept
{
    return (static_cast<std::uint32_t>(bytes[0]) << 24U) | (static_cast<std::uint32_t>(bytes[1]) << 16U) |
           (static_cast<std::uint32_t>(bytes[2]) << 8U) | static_cast<std::uint32_t>(bytes[3]);
}

std::uint32_t read_le32(const std::vector<std::uint8_t>& bytes) noexcept
{
    return (static_cast<std::uint32_t>(bytes[3]) << 24U) | (static_cast<std::uint32_t>(bytes[2]) << 16U) |
           (static_cast<std::uint32_t>(bytes[1]) << 8U) | static_cast<std::uint32_t>(bytes[0]);
}

} // namespace

Format detect_format(const std::vector<std::uint8_t>& bytes) noexcept
{
    if (bytes.size() >= 4U && bytes[0] == 0x7fU && bytes[1] == 'E' && bytes[2] == 'L' && bytes[3] == 'F') {
        return Format::Elf;
    }

    static constexpr std::array<std::uint8_t, 8> archive_magic{'!', '<', 'a', 'r', 'c', 'h', '>', '\n'};
    if (bytes.size() >= archive_magic.size() &&
        std::equal(archive_magic.begin(), archive_magic.end(), bytes.begin())) {
        return Format::Archive;
    }

    if (bytes.size() >= 4U) {
        const std::uint32_t be = read_be32(bytes);
        const std::uint32_t le = read_le32(bytes);
        if (be == 0xCAFEBABEU || be == 0xBEBAFECAU || le == 0xCAFEBABEU) {
            return Format::MachOFat;
        }
        if (be == 0xFEEDFACEU || be == 0xFEEDFACFU || le == 0xFEEDFACEU || le == 0xFEEDFACFU) {
            return Format::MachO;
        }
    }

    // PE files begin with the "MZ" DOS stub.
    if (bytes.size() >= 2U && bytes[0] == 'M' && bytes[1] == 'Z') {
        return Format::PeCoff;
    }

    return Format::Unknown;
}

Result<std::unique_ptr<BinaryFile>> load_bytes(std::string source_name, std::vector<std::uint8_t> bytes)
{
    const Format format = detect_format(bytes);
    switch (format) {
    case Format::Elf:
        return elf::open_bytes(std::move(source_name), std::move(bytes));
    case Format::MachO:
    case Format::MachOFat:
        return macho::open_bytes(std::move(source_name), std::move(bytes));
    case Format::PeCoff:
        return pe::open_bytes(std::move(source_name), std::move(bytes));
    case Format::Archive:
        return Result<std::unique_ptr<BinaryFile>>::err(make_error(
            ErrorCode::UnsupportedFormat,
            "static archives are detected but not yet parsed by roe; extract members and inspect them individually"));
    case Format::Unknown:
        break;
    }

    return Result<std::unique_ptr<BinaryFile>>::err(make_error(
        ErrorCode::UnsupportedFormat,
        "unrecognized file format; first bytes: " + first_bytes_hex(bytes)));
}

Result<std::unique_ptr<BinaryFile>> load_file(const std::filesystem::path& path)
{
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        return Result<std::unique_ptr<BinaryFile>>::err(
            make_error(ErrorCode::FileIo, "failed to open file: " + path.string()));
    }

    std::vector<std::uint8_t> bytes;
    stream.unsetf(std::ios::skipws);
    bytes.assign(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
    if (!stream.eof() && stream.fail()) {
        return Result<std::unique_ptr<BinaryFile>>::err(
            make_error(ErrorCode::FileIo, "failed to read file: " + path.string()));
    }

    return load_bytes(path.string(), std::move(bytes));
}

std::optional<Object> primary_object(const FileView& file)
{
    if (file.objects.empty()) {
        return std::nullopt;
    }
    return file.objects.front();
}

std::optional<Section> find_section(const FileView& file, std::size_t object_index, std::string_view name)
{
    if (object_index >= file.objects.size()) {
        return std::nullopt;
    }
    const Object& object = file.objects[object_index];
    const auto found = std::find_if(object.sections.begin(), object.sections.end(), [&](const Section& section) {
        return section.name == name;
    });
    if (found == object.sections.end()) {
        return std::nullopt;
    }
    return *found;
}

std::vector<Symbol> function_symbols(const FileView& file, std::size_t object_index)
{
    std::vector<Symbol> functions;
    if (object_index >= file.objects.size()) {
        return functions;
    }
    for (const Symbol& symbol : file.objects[object_index].symbols) {
        if (symbol.type == SymbolType::Function && symbol.defined) {
            functions.push_back(symbol);
        }
    }
    return functions;
}

std::optional<Symbol> find_symbol(const FileView& file, std::size_t object_index, std::string_view name)
{
    if (object_index >= file.objects.size()) {
        return std::nullopt;
    }
    const Object& object = file.objects[object_index];
    const auto found = std::find_if(object.symbols.begin(), object.symbols.end(), [&](const Symbol& symbol) {
        return symbol.name == name || symbol.raw_name == name;
    });
    if (found == object.symbols.end()) {
        return std::nullopt;
    }
    return *found;
}

std::string_view format_name(Format format) noexcept
{
    switch (format) {
    case Format::Unknown:
        return "unknown";
    case Format::Elf:
        return "ELF";
    case Format::MachO:
        return "Mach-O";
    case Format::MachOFat:
        return "Mach-O universal";
    case Format::PeCoff:
        return "PE/COFF";
    case Format::Archive:
        return "static archive";
    }
    return "unknown";
}

std::string_view architecture_name(Architecture architecture) noexcept
{
    switch (architecture) {
    case Architecture::Unknown:
        return "unknown";
    case Architecture::X86:
        return "x86";
    case Architecture::X86_64:
        return "x86-64";
    case Architecture::Arm:
        return "arm";
    case Architecture::ArmThumb:
        return "arm-thumb";
    case Architecture::AArch64:
        return "aarch64";
    case Architecture::RiscV32:
        return "riscv32";
    case Architecture::RiscV64:
        return "riscv64";
    case Architecture::Mips32:
        return "mips";
    case Architecture::Mips32el:
        return "mipsel";
    case Architecture::Mips64:
        return "mips64";
    case Architecture::Mips64el:
        return "mips64el";
    case Architecture::PowerPc32:
        return "ppc";
    case Architecture::PowerPc64:
        return "ppc64";
    case Architecture::PowerPc64le:
        return "ppc64le";
    }
    return "unknown";
}

std::string first_bytes_hex(const std::vector<std::uint8_t>& bytes, std::size_t limit)
{
    std::ostringstream out;
    const std::size_t count = std::min(limit, bytes.size());
    for (std::size_t index = 0; index < count; ++index) {
        if (index != 0) {
            out << ' ';
        }
        out << std::hex << std::nouppercase << std::setfill('0') << std::setw(2)
            << static_cast<unsigned int>(bytes[index]);
    }
    if (count == 0) {
        out << "(empty)";
    }
    return out.str();
}

} // namespace roe::binary
