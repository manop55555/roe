#include "roe/elf.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <limits>
#include <memory>
#include <string>
#include <utility>

#if __has_include(<cxxabi.h>)
#include <cxxabi.h>
#define ROE_ELF_HAS_CXXABI 1
#else
#define ROE_ELF_HAS_CXXABI 0
#endif

namespace roe::elf {
namespace {

constexpr std::uint8_t elf_magic_0 = 0x7fU;
constexpr std::uint8_t elf_magic_1 = 'E';
constexpr std::uint8_t elf_magic_2 = 'L';
constexpr std::uint8_t elf_magic_3 = 'F';
constexpr std::size_t elf_ident_size = 16U;

constexpr std::uint8_t elf_class_32 = 1U;
constexpr std::uint8_t elf_class_64 = 2U;
constexpr std::uint8_t elf_data_lsb = 1U;
constexpr std::uint8_t elf_data_msb = 2U;
constexpr std::uint8_t elf_current_version = 1U;

constexpr std::uint16_t et_none = 0U;
constexpr std::uint16_t et_rel = 1U;
constexpr std::uint16_t et_exec = 2U;
constexpr std::uint16_t et_dyn = 3U;
constexpr std::uint16_t et_core = 4U;

constexpr std::uint16_t em_386 = 3U;
constexpr std::uint16_t em_x86_64 = 62U;
constexpr std::uint16_t em_aarch64 = 183U;

constexpr std::uint32_t sht_symtab = 2U;
constexpr std::uint32_t sht_strtab = 3U;
constexpr std::uint32_t sht_rela = 4U;
constexpr std::uint32_t sht_nobits = 8U;
constexpr std::uint32_t sht_rel = 9U;
constexpr std::uint32_t sht_dynsym = 11U;

constexpr std::uint64_t shf_execinstr = 0x4U;

constexpr std::uint16_t shn_undef = 0U;
constexpr std::uint16_t shn_xindex = 0xffffU;
constexpr std::uint16_t pn_xnum = 0xffffU;

constexpr std::uint16_t elf32_ehdr_size = 52U;
constexpr std::uint16_t elf64_ehdr_size = 64U;
constexpr std::uint16_t elf32_phdr_size = 32U;
constexpr std::uint16_t elf64_phdr_size = 56U;
constexpr std::uint16_t elf32_shdr_size = 40U;
constexpr std::uint16_t elf64_shdr_size = 64U;
constexpr std::uint16_t elf32_sym_size = 16U;
constexpr std::uint16_t elf64_sym_size = 24U;
constexpr std::uint16_t elf32_rel_size = 8U;
constexpr std::uint16_t elf64_rel_size = 16U;
constexpr std::uint16_t elf32_rela_size = 12U;
constexpr std::uint16_t elf64_rela_size = 24U;

struct Header {
    Class elf_class{Class::Elf64};
    Endianness endianness{Endianness::Little};
    std::uint16_t type{0};
    std::uint16_t machine{0};
    std::uint64_t entry{0};
    std::uint64_t program_header_offset{0};
    std::uint64_t section_header_offset{0};
    std::uint16_t header_size{0};
    std::uint16_t program_header_entry_size{0};
    std::uint64_t program_header_count{0};
    std::uint16_t section_header_entry_size{0};
    std::uint64_t section_header_count{0};
    std::uint64_t section_name_index{0};
};

struct RawSection {
    Section section;
    std::uint32_t name_offset{0};
    std::uint32_t link{0};
    std::uint32_t info{0};
    std::uint64_t entry_size{0};
};

struct ByteRange {
    const std::uint8_t* data{nullptr};
    std::uint64_t size{0};
};

Error make_error(ErrorCode code, std::string message, std::uint64_t offset = 0, bool has_offset = false)
{
    return Error{code, std::move(message), offset, has_offset};
}

bool checked_add(std::uint64_t lhs, std::uint64_t rhs, std::uint64_t& out) noexcept
{
    if (lhs > std::numeric_limits<std::uint64_t>::max() - rhs) {
        return false;
    }
    out = lhs + rhs;
    return true;
}

bool range_within(std::uint64_t offset, std::uint64_t size, std::uint64_t image_size) noexcept
{
    std::uint64_t end = 0;
    return checked_add(offset, size, end) && end <= image_size;
}

Result<void> validate_range(std::uint64_t offset, std::uint64_t size, std::uint64_t image_size, std::string label)
{
    if (!range_within(offset, size, image_size)) {
        return Result<void>::err(make_error(
            ErrorCode::MalformedInput,
            std::move(label) + " extends past end of file",
            offset,
            true));
    }
    return Result<void>::ok();
}

class Reader {
public:
    Reader(const std::vector<std::uint8_t>& bytes, Endianness endianness) noexcept
        : bytes_(bytes), endianness_(endianness)
    {
    }

    Result<std::uint8_t> u8(std::uint64_t offset) const
    {
        if (!range_within(offset, 1U, bytes_.size())) {
            return Result<std::uint8_t>::err(make_error(ErrorCode::MalformedInput, "read past end of file", offset, true));
        }
        return Result<std::uint8_t>::ok(bytes_[static_cast<std::size_t>(offset)]);
    }

    Result<std::uint16_t> u16(std::uint64_t offset) const
    {
        const auto bytes = read_array(offset, 2U);
        if (!bytes) {
            return Result<std::uint16_t>::err(std::move(bytes).error());
        }
        const auto* ptr = bytes.value();
        if (endianness_ == Endianness::Little) {
            return Result<std::uint16_t>::ok(static_cast<std::uint16_t>(ptr[0] | (static_cast<std::uint16_t>(ptr[1]) << 8U)));
        }
        return Result<std::uint16_t>::ok(static_cast<std::uint16_t>((static_cast<std::uint16_t>(ptr[0]) << 8U) | ptr[1]));
    }

    Result<std::uint32_t> u32(std::uint64_t offset) const
    {
        const auto bytes = read_array(offset, 4U);
        if (!bytes) {
            return Result<std::uint32_t>::err(std::move(bytes).error());
        }
        const auto* ptr = bytes.value();
        if (endianness_ == Endianness::Little) {
            return Result<std::uint32_t>::ok(static_cast<std::uint32_t>(
                ptr[0] | (static_cast<std::uint32_t>(ptr[1]) << 8U) | (static_cast<std::uint32_t>(ptr[2]) << 16U) |
                (static_cast<std::uint32_t>(ptr[3]) << 24U)));
        }
        return Result<std::uint32_t>::ok(static_cast<std::uint32_t>(
            (static_cast<std::uint32_t>(ptr[0]) << 24U) | (static_cast<std::uint32_t>(ptr[1]) << 16U) |
            (static_cast<std::uint32_t>(ptr[2]) << 8U) | ptr[3]));
    }

    Result<std::uint64_t> u64(std::uint64_t offset) const
    {
        const auto bytes = read_array(offset, 8U);
        if (!bytes) {
            return Result<std::uint64_t>::err(std::move(bytes).error());
        }
        const auto* ptr = bytes.value();
        std::uint64_t value = 0;
        if (endianness_ == Endianness::Little) {
            for (std::size_t i = 0; i < 8U; ++i) {
                value |= static_cast<std::uint64_t>(ptr[i]) << (i * 8U);
            }
        } else {
            for (std::size_t i = 0; i < 8U; ++i) {
                value = (value << 8U) | ptr[i];
            }
        }
        return Result<std::uint64_t>::ok(value);
    }

    Result<std::int32_t> i32(std::uint64_t offset) const
    {
        const auto value = u32(offset);
        if (!value) {
            return Result<std::int32_t>::err(std::move(value).error());
        }
        return Result<std::int32_t>::ok(static_cast<std::int32_t>(value.value()));
    }

    Result<std::int64_t> i64(std::uint64_t offset) const
    {
        const auto value = u64(offset);
        if (!value) {
            return Result<std::int64_t>::err(std::move(value).error());
        }
        return Result<std::int64_t>::ok(static_cast<std::int64_t>(value.value()));
    }

private:
    Result<const std::uint8_t*> read_array(std::uint64_t offset, std::uint64_t size) const
    {
        if (!range_within(offset, size, bytes_.size())) {
            return Result<const std::uint8_t*>::err(make_error(ErrorCode::MalformedInput, "read past end of file", offset, true));
        }
        return Result<const std::uint8_t*>::ok(bytes_.data() + static_cast<std::ptrdiff_t>(offset));
    }

    const std::vector<std::uint8_t>& bytes_;
    Endianness endianness_;
};

FileType map_file_type(std::uint16_t value) noexcept
{
    switch (value) {
    case et_none:
        return FileType::None;
    case et_rel:
        return FileType::Relocatable;
    case et_exec:
        return FileType::Executable;
    case et_dyn:
        return FileType::SharedObject;
    case et_core:
        return FileType::Core;
    default:
        return FileType::Other;
    }
}

Machine map_machine(std::uint16_t value) noexcept
{
    switch (value) {
    case em_386:
        return Machine::X86;
    case em_x86_64:
        return Machine::X86_64;
    case em_aarch64:
        return Machine::AArch64;
    default:
        return Machine::Other;
    }
}

SymbolBind map_symbol_bind(std::uint8_t value) noexcept
{
    switch (value) {
    case 0:
        return SymbolBind::Local;
    case 1:
        return SymbolBind::Global;
    case 2:
        return SymbolBind::Weak;
    default:
        return SymbolBind::Other;
    }
}

SymbolType map_symbol_type(std::uint8_t value) noexcept
{
    switch (value) {
    case 0:
        return SymbolType::NoType;
    case 1:
        return SymbolType::Object;
    case 2:
        return SymbolType::Function;
    case 3:
        return SymbolType::Section;
    case 4:
        return SymbolType::File;
    case 5:
        return SymbolType::Common;
    case 6:
        return SymbolType::Tls;
    default:
        return SymbolType::Other;
    }
}

Result<ByteRange> range_for_section(const std::vector<std::uint8_t>& image, const RawSection& section)
{
    if (section.section.type == sht_nobits) {
        return Result<ByteRange>::ok(ByteRange{nullptr, 0U});
    }
    const auto valid = validate_range(section.section.offset, section.section.size, image.size(), "section '" + section.section.name + "'");
    if (!valid) {
        return Result<ByteRange>::err(std::move(valid).error());
    }
    const auto* data = image.data() + static_cast<std::ptrdiff_t>(section.section.offset);
    return Result<ByteRange>::ok(ByteRange{data, section.section.size});
}

Result<std::string> string_from_table(ByteRange table, std::uint32_t offset, std::string table_name)
{
    if (offset == 0U) {
        return Result<std::string>::ok(std::string{});
    }
    if (table.data == nullptr || offset >= table.size) {
        return Result<std::string>::err(make_error(
            ErrorCode::MalformedInput,
            "string offset is outside " + std::move(table_name),
            offset,
            true));
    }
    const auto start = static_cast<std::uint64_t>(offset);
    std::uint64_t end = start;
    while (end < table.size && table.data[static_cast<std::size_t>(end)] != 0U) {
        ++end;
    }
    if (end == table.size) {
        return Result<std::string>::err(make_error(ErrorCode::MalformedInput, "unterminated string in " + std::move(table_name), offset, true));
    }
    const auto* begin = reinterpret_cast<const char*>(table.data + static_cast<std::ptrdiff_t>(start));
    return Result<std::string>::ok(std::string(begin, static_cast<std::size_t>(end - start)));
}

Result<Header> parse_header(const std::vector<std::uint8_t>& bytes)
{
    if (bytes.size() < elf_ident_size) {
        return Result<Header>::err(make_error(ErrorCode::MalformedInput, "file is too small to be an ELF file"));
    }
    if (bytes[0] != elf_magic_0 || bytes[1] != elf_magic_1 || bytes[2] != elf_magic_2 || bytes[3] != elf_magic_3) {
        return Result<Header>::err(make_error(ErrorCode::UnsupportedFormat, "input is not an ELF file"));
    }

    Header header;
    if (bytes[4] == elf_class_32) {
        header.elf_class = Class::Elf32;
    } else if (bytes[4] == elf_class_64) {
        header.elf_class = Class::Elf64;
    } else {
        return Result<Header>::err(make_error(ErrorCode::UnsupportedFormat, "unsupported ELF class", 4U, true));
    }

    if (bytes[5] == elf_data_lsb) {
        header.endianness = Endianness::Little;
    } else if (bytes[5] == elf_data_msb) {
        header.endianness = Endianness::Big;
    } else {
        return Result<Header>::err(make_error(ErrorCode::UnsupportedFormat, "unsupported ELF endianness", 5U, true));
    }

    if (bytes[6] != elf_current_version) {
        return Result<Header>::err(make_error(ErrorCode::UnsupportedFormat, "unsupported ELF ident version", 6U, true));
    }

    const Reader reader(bytes, header.endianness);
    const std::uint64_t minimum_header_size = header.elf_class == Class::Elf64 ? elf64_ehdr_size : elf32_ehdr_size;
    const auto header_range = validate_range(0U, minimum_header_size, bytes.size(), "ELF header");
    if (!header_range) {
        return Result<Header>::err(std::move(header_range).error());
    }

    auto type = reader.u16(16U);
    auto machine = reader.u16(18U);
    auto file_version = reader.u32(20U);
    if (!type || !machine || !file_version) {
        return Result<Header>::err(make_error(ErrorCode::MalformedInput, "failed to read ELF header"));
    }
    if (file_version.value() != elf_current_version) {
        return Result<Header>::err(make_error(ErrorCode::UnsupportedFormat, "unsupported ELF header version", 20U, true));
    }

    header.type = type.value();
    header.machine = machine.value();
    if (header.elf_class == Class::Elf64) {
        header.entry = reader.u64(24U).value();
        header.program_header_offset = reader.u64(32U).value();
        header.section_header_offset = reader.u64(40U).value();
        header.header_size = reader.u16(52U).value();
        header.program_header_entry_size = reader.u16(54U).value();
        header.program_header_count = reader.u16(56U).value();
        header.section_header_entry_size = reader.u16(58U).value();
        header.section_header_count = reader.u16(60U).value();
        header.section_name_index = reader.u16(62U).value();
    } else {
        header.entry = reader.u32(24U).value();
        header.program_header_offset = reader.u32(28U).value();
        header.section_header_offset = reader.u32(32U).value();
        header.header_size = reader.u16(40U).value();
        header.program_header_entry_size = reader.u16(42U).value();
        header.program_header_count = reader.u16(44U).value();
        header.section_header_entry_size = reader.u16(46U).value();
        header.section_header_count = reader.u16(48U).value();
        header.section_name_index = reader.u16(50U).value();
    }

    if (header.header_size < minimum_header_size) {
        return Result<Header>::err(make_error(ErrorCode::MalformedInput, "ELF header reports an invalid size", header.header_size, true));
    }
    if (header.program_header_count > 0U && header.program_header_entry_size < (header.elf_class == Class::Elf64 ? elf64_phdr_size : elf32_phdr_size)) {
        return Result<Header>::err(make_error(ErrorCode::MalformedInput, "program header entry size is too small"));
    }
    if (header.section_header_count > 0U && header.section_header_entry_size < (header.elf_class == Class::Elf64 ? elf64_shdr_size : elf32_shdr_size)) {
        return Result<Header>::err(make_error(ErrorCode::MalformedInput, "section header entry size is too small"));
    }

    return Result<Header>::ok(header);
}

Result<RawSection> parse_section_header(const Reader& reader, const Header& header, std::uint64_t offset, std::uint16_t index)
{
    RawSection raw;
    raw.section.index = index;

    const auto name = reader.u32(offset);
    const auto type = reader.u32(offset + 4U);
    if (!name || !type) {
        return Result<RawSection>::err(make_error(ErrorCode::MalformedInput, "failed to read section header", offset, true));
    }
    raw.name_offset = name.value();
    raw.section.type = type.value();

    if (header.elf_class == Class::Elf64) {
        const auto flags = reader.u64(offset + 8U);
        const auto address = reader.u64(offset + 16U);
        const auto section_offset = reader.u64(offset + 24U);
        const auto size = reader.u64(offset + 32U);
        const auto link = reader.u32(offset + 40U);
        const auto info = reader.u32(offset + 44U);
        const auto alignment = reader.u64(offset + 48U);
        const auto entry_size = reader.u64(offset + 56U);
        if (!flags || !address || !section_offset || !size || !link || !info || !alignment || !entry_size) {
            return Result<RawSection>::err(make_error(ErrorCode::MalformedInput, "failed to read section header", offset, true));
        }
        raw.section.flags = flags.value();
        raw.section.address = address.value();
        raw.section.offset = section_offset.value();
        raw.section.size = size.value();
        raw.link = link.value();
        raw.info = info.value();
        raw.section.alignment = alignment.value();
        raw.entry_size = entry_size.value();
    } else {
        const auto flags = reader.u32(offset + 8U);
        const auto address = reader.u32(offset + 12U);
        const auto section_offset = reader.u32(offset + 16U);
        const auto size = reader.u32(offset + 20U);
        const auto link = reader.u32(offset + 24U);
        const auto info = reader.u32(offset + 28U);
        const auto alignment = reader.u32(offset + 32U);
        const auto entry_size = reader.u32(offset + 36U);
        if (!flags || !address || !section_offset || !size || !link || !info || !alignment || !entry_size) {
            return Result<RawSection>::err(make_error(ErrorCode::MalformedInput, "failed to read section header", offset, true));
        }
        raw.section.flags = flags.value();
        raw.section.address = address.value();
        raw.section.offset = section_offset.value();
        raw.section.size = size.value();
        raw.link = link.value();
        raw.info = info.value();
        raw.section.alignment = alignment.value();
        raw.entry_size = entry_size.value();
    }
    raw.section.executable = (raw.section.flags & shf_execinstr) != 0U;
    return Result<RawSection>::ok(raw);
}

Result<std::vector<RawSection>> parse_section_headers(const std::vector<std::uint8_t>& bytes, Header& header)
{
    std::vector<RawSection> sections;
    if (header.section_header_count == 0U && header.section_header_offset == 0U) {
        return Result<std::vector<RawSection>>::ok(sections);
    }
    if (header.section_header_entry_size == 0U) {
        return Result<std::vector<RawSection>>::err(make_error(ErrorCode::MalformedInput, "section header entry size is zero"));
    }

    const Reader reader(bytes, header.endianness);
    if (header.section_header_count == 0U || header.section_name_index == shn_xindex || header.program_header_count == pn_xnum) {
        const auto first_range = validate_range(header.section_header_offset, header.section_header_entry_size, bytes.size(), "section header table");
        if (!first_range) {
            return Result<std::vector<RawSection>>::err(std::move(first_range).error());
        }
        auto first = parse_section_header(reader, header, header.section_header_offset, 0U);
        if (!first) {
            return Result<std::vector<RawSection>>::err(std::move(first).error());
        }
        if (header.section_header_count == 0U) {
            header.section_header_count = first.value().section.size;
        }
        if (header.section_name_index == shn_xindex) {
            header.section_name_index = first.value().link;
        }
        if (header.program_header_count == pn_xnum) {
            header.program_header_count = first.value().info;
        }
    }

    const std::uint64_t total_size = header.section_header_count * static_cast<std::uint64_t>(header.section_header_entry_size);
    if (header.section_header_count != 0U && total_size / header.section_header_count != header.section_header_entry_size) {
        return Result<std::vector<RawSection>>::err(make_error(ErrorCode::MalformedInput, "section header table size overflows"));
    }
    const auto table_range = validate_range(header.section_header_offset, total_size, bytes.size(), "section header table");
    if (!table_range) {
        return Result<std::vector<RawSection>>::err(std::move(table_range).error());
    }
    if (header.section_header_count > std::numeric_limits<std::uint16_t>::max()) {
        return Result<std::vector<RawSection>>::err(make_error(ErrorCode::MalformedInput, "too many sections for public model"));
    }

    sections.reserve(static_cast<std::size_t>(header.section_header_count));
    for (std::uint64_t i = 0; i < header.section_header_count; ++i) {
        const auto offset = header.section_header_offset + (i * header.section_header_entry_size);
        auto section = parse_section_header(reader, header, offset, static_cast<std::uint16_t>(i));
        if (!section) {
            return Result<std::vector<RawSection>>::err(std::move(section).error());
        }
        sections.push_back(std::move(section).value());
    }

    if (header.section_name_index >= sections.size() && !sections.empty()) {
        return Result<std::vector<RawSection>>::err(make_error(ErrorCode::MalformedInput, "section name string table index is invalid"));
    }

    if (!sections.empty()) {
        auto names = range_for_section(bytes, sections[static_cast<std::size_t>(header.section_name_index)]);
        if (!names) {
            return Result<std::vector<RawSection>>::err(std::move(names).error());
        }
        for (auto& section : sections) {
            auto section_name = string_from_table(names.value(), section.name_offset, "section name string table");
            if (!section_name) {
                return Result<std::vector<RawSection>>::err(std::move(section_name).error());
            }
            section.section.name = std::move(section_name).value();
        }
    }

    for (const auto& section : sections) {
        if (section.section.type == sht_nobits) {
            continue;
        }
        const auto valid = validate_range(section.section.offset, section.section.size, bytes.size(), "section '" + section.section.name + "'");
        if (!valid) {
            return Result<std::vector<RawSection>>::err(std::move(valid).error());
        }
    }

    return Result<std::vector<RawSection>>::ok(std::move(sections));
}

Result<std::vector<Segment>> parse_segments(const std::vector<std::uint8_t>& bytes, const Header& header)
{
    std::vector<Segment> segments;
    if (header.program_header_count == 0U) {
        return Result<std::vector<Segment>>::ok(segments);
    }
    if (header.program_header_entry_size == 0U) {
        return Result<std::vector<Segment>>::err(make_error(ErrorCode::MalformedInput, "program header entry size is zero"));
    }
    const std::uint64_t total_size = header.program_header_count * static_cast<std::uint64_t>(header.program_header_entry_size);
    if (total_size / header.program_header_count != header.program_header_entry_size) {
        return Result<std::vector<Segment>>::err(make_error(ErrorCode::MalformedInput, "program header table size overflows"));
    }
    const auto table_range = validate_range(header.program_header_offset, total_size, bytes.size(), "program header table");
    if (!table_range) {
        return Result<std::vector<Segment>>::err(std::move(table_range).error());
    }

    const Reader reader(bytes, header.endianness);
    segments.reserve(static_cast<std::size_t>(header.program_header_count));
    for (std::uint64_t i = 0; i < header.program_header_count; ++i) {
        const auto offset = header.program_header_offset + (i * header.program_header_entry_size);
        Segment segment;
        segment.type = reader.u32(offset).value();
        if (header.elf_class == Class::Elf64) {
            segment.flags = reader.u32(offset + 4U).value();
            segment.offset = reader.u64(offset + 8U).value();
            segment.virtual_address = reader.u64(offset + 16U).value();
            segment.physical_address = reader.u64(offset + 24U).value();
            segment.file_size = reader.u64(offset + 32U).value();
            segment.memory_size = reader.u64(offset + 40U).value();
            segment.alignment = reader.u64(offset + 48U).value();
        } else {
            segment.offset = reader.u32(offset + 4U).value();
            segment.virtual_address = reader.u32(offset + 8U).value();
            segment.physical_address = reader.u32(offset + 12U).value();
            segment.file_size = reader.u32(offset + 16U).value();
            segment.memory_size = reader.u32(offset + 20U).value();
            segment.flags = reader.u32(offset + 24U).value();
            segment.alignment = reader.u32(offset + 28U).value();
        }
        const auto valid = validate_range(segment.offset, segment.file_size, bytes.size(), "segment");
        if (!valid) {
            return Result<std::vector<Segment>>::err(std::move(valid).error());
        }
        segments.push_back(segment);
    }
    return Result<std::vector<Segment>>::ok(std::move(segments));
}

Result<Symbol> parse_symbol(const Reader& reader, const Header& header, ByteRange string_table, std::uint64_t offset, bool dynamic)
{
    Symbol symbol;
    symbol.dynamic = dynamic;

    std::uint32_t name_offset = 0;
    std::uint8_t info = 0;
    if (header.elf_class == Class::Elf64) {
        name_offset = reader.u32(offset).value();
        info = reader.u8(offset + 4U).value();
        symbol.section_index = reader.u16(offset + 6U).value();
        symbol.address = reader.u64(offset + 8U).value();
        symbol.size = reader.u64(offset + 16U).value();
    } else {
        name_offset = reader.u32(offset).value();
        symbol.address = reader.u32(offset + 4U).value();
        symbol.size = reader.u32(offset + 8U).value();
        info = reader.u8(offset + 12U).value();
        symbol.section_index = reader.u16(offset + 14U).value();
    }

    auto name = string_from_table(string_table, name_offset, "symbol string table");
    if (!name) {
        return Result<Symbol>::err(std::move(name).error());
    }
    symbol.name = std::move(name).value();
    symbol.bind = map_symbol_bind(static_cast<std::uint8_t>(info >> 4U));
    symbol.type = map_symbol_type(static_cast<std::uint8_t>(info & 0x0fU));
    symbol.defined = symbol.section_index != shn_undef;
    return Result<Symbol>::ok(std::move(symbol));
}

Result<std::vector<std::vector<Symbol>>> parse_symbols(
    const std::vector<std::uint8_t>& bytes,
    const Header& header,
    const std::vector<RawSection>& sections,
    File& file)
{
    std::vector<std::vector<Symbol>> by_section(sections.size());
    const Reader reader(bytes, header.endianness);

    for (std::size_t i = 0; i < sections.size(); ++i) {
        const auto& section = sections[i];
        if (section.section.type != sht_symtab && section.section.type != sht_dynsym) {
            continue;
        }
        const std::uint64_t expected_entry_size = header.elf_class == Class::Elf64 ? elf64_sym_size : elf32_sym_size;
        const std::uint64_t entry_size = section.entry_size == 0U ? expected_entry_size : section.entry_size;
        if (entry_size < expected_entry_size) {
            return Result<std::vector<std::vector<Symbol>>>::err(make_error(ErrorCode::MalformedInput, "symbol table entry size is too small"));
        }
        if (section.section.size % entry_size != 0U) {
            return Result<std::vector<std::vector<Symbol>>>::err(make_error(ErrorCode::MalformedInput, "symbol table size is not a multiple of entry size"));
        }
        if (section.link >= sections.size()) {
            return Result<std::vector<std::vector<Symbol>>>::err(make_error(ErrorCode::MalformedInput, "symbol table string table link is invalid"));
        }
        auto strings = range_for_section(bytes, sections[section.link]);
        if (!strings) {
            return Result<std::vector<std::vector<Symbol>>>::err(std::move(strings).error());
        }
        if (sections[section.link].section.type != sht_strtab) {
            return Result<std::vector<std::vector<Symbol>>>::err(make_error(ErrorCode::MalformedInput, "symbol table link does not point to a string table"));
        }

        const std::uint64_t count = section.section.size / entry_size;
        by_section[i].reserve(static_cast<std::size_t>(count));
        for (std::uint64_t entry = 0; entry < count; ++entry) {
            auto symbol = parse_symbol(reader, header, strings.value(), section.section.offset + (entry * entry_size), section.section.type == sht_dynsym);
            if (!symbol) {
                return Result<std::vector<std::vector<Symbol>>>::err(std::move(symbol).error());
            }
            by_section[i].push_back(symbol.value());
            file.symbols.push_back(std::move(symbol).value());
        }
    }

    return Result<std::vector<std::vector<Symbol>>>::ok(std::move(by_section));
}

Result<void> parse_relocations(
    const std::vector<std::uint8_t>& bytes,
    const Header& header,
    const std::vector<RawSection>& sections,
    const std::vector<std::vector<Symbol>>& symbols_by_section,
    File& file)
{
    const Reader reader(bytes, header.endianness);

    for (const auto& section : sections) {
        if (section.section.type != sht_rel && section.section.type != sht_rela) {
            continue;
        }
        if (section.link >= sections.size()) {
            return Result<void>::err(make_error(ErrorCode::MalformedInput, "relocation symbol table link is invalid"));
        }
        if (section.link >= symbols_by_section.size()) {
            return Result<void>::err(make_error(ErrorCode::MalformedInput, "relocation symbol table is unavailable"));
        }
        const std::uint64_t expected_entry_size = [&]() {
            if (header.elf_class == Class::Elf64) {
                return section.section.type == sht_rela ? static_cast<std::uint64_t>(elf64_rela_size) : static_cast<std::uint64_t>(elf64_rel_size);
            }
            return section.section.type == sht_rela ? static_cast<std::uint64_t>(elf32_rela_size) : static_cast<std::uint64_t>(elf32_rel_size);
        }();
        const std::uint64_t entry_size = section.entry_size == 0U ? expected_entry_size : section.entry_size;
        if (entry_size < expected_entry_size) {
            return Result<void>::err(make_error(ErrorCode::MalformedInput, "relocation entry size is too small"));
        }
        if (section.section.size % entry_size != 0U) {
            return Result<void>::err(make_error(ErrorCode::MalformedInput, "relocation table size is not a multiple of entry size"));
        }

        const auto& symbol_table = symbols_by_section[section.link];
        const std::uint64_t count = section.section.size / entry_size;
        for (std::uint64_t entry = 0; entry < count; ++entry) {
            const auto offset = section.section.offset + (entry * entry_size);
            Relocation relocation;
            relocation.section_name = section.section.name;
            relocation.has_addend = section.section.type == sht_rela;

            std::uint64_t info = 0;
            if (header.elf_class == Class::Elf64) {
                relocation.offset = reader.u64(offset).value();
                info = reader.u64(offset + 8U).value();
                relocation.symbol_index = info >> 32U;
                relocation.type = static_cast<std::uint32_t>(info & 0xffffffffULL);
                if (relocation.has_addend) {
                    relocation.addend = reader.i64(offset + 16U).value();
                }
            } else {
                relocation.offset = reader.u32(offset).value();
                info = reader.u32(offset + 4U).value();
                relocation.symbol_index = info >> 8U;
                relocation.type = static_cast<std::uint32_t>(info & 0xffU);
                if (relocation.has_addend) {
                    relocation.addend = reader.i32(offset + 8U).value();
                }
            }

            if (relocation.symbol_index >= symbol_table.size()) {
                return Result<void>::err(make_error(ErrorCode::MalformedInput, "relocation references invalid symbol index"));
            }
            relocation.symbol_name = symbol_table[static_cast<std::size_t>(relocation.symbol_index)].name;
            file.relocations.push_back(std::move(relocation));
        }
    }

    return Result<void>::ok();
}

std::string maybe_demangle(std::string_view name)
{
#if ROE_ELF_HAS_CXXABI
    int status = 0;
    using FreeDeleter = void (*)(void*);
    std::unique_ptr<char, FreeDeleter> demangled(abi::__cxa_demangle(std::string(name).c_str(), nullptr, nullptr, &status), std::free);
    if (status == 0 && demangled != nullptr) {
        return std::string(demangled.get());
    }
#endif
    return std::string(name);
}

} // namespace

Result<File> parse_file(const std::filesystem::path& path)
{
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        return Result<File>::err(make_error(ErrorCode::FileIo, "failed to open file: " + path.string()));
    }

    std::vector<std::uint8_t> bytes;
    stream.unsetf(std::ios::skipws);
    bytes.assign(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
    if (!stream.eof() && stream.fail()) {
        return Result<File>::err(make_error(ErrorCode::FileIo, "failed to read file: " + path.string()));
    }

    return parse_bytes(path.string(), std::move(bytes));
}

Result<File> parse_bytes(std::string source_name, std::vector<std::uint8_t> bytes)
{
    auto header_result = parse_header(bytes);
    if (!header_result) {
        return Result<File>::err(std::move(header_result).error());
    }
    Header header = header_result.value();

    auto raw_sections = parse_section_headers(bytes, header);
    if (!raw_sections) {
        return Result<File>::err(std::move(raw_sections).error());
    }
    auto segments = parse_segments(bytes, header);
    if (!segments) {
        return Result<File>::err(std::move(segments).error());
    }

    File file;
    file.source_name = std::move(source_name);
    file.image = std::move(bytes);
    file.elf_class = header.elf_class;
    file.endianness = header.endianness;
    file.file_type = map_file_type(header.type);
    file.machine = map_machine(header.machine);
    file.entry = header.entry;
    file.segments = std::move(segments).value();

    file.sections.reserve(raw_sections.value().size());
    bool has_static_symbol_table = false;
    for (const auto& section : raw_sections.value()) {
        if (section.section.type == sht_symtab) {
            has_static_symbol_table = true;
        }
        file.sections.push_back(section.section);
    }
    file.stripped = !has_static_symbol_table;

    auto symbols = parse_symbols(file.image, header, raw_sections.value(), file);
    if (!symbols) {
        return Result<File>::err(std::move(symbols).error());
    }

    auto relocations = parse_relocations(file.image, header, raw_sections.value(), symbols.value(), file);
    if (!relocations) {
        return Result<File>::err(std::move(relocations).error());
    }

    return Result<File>::ok(std::move(file));
}

std::optional<Section> find_section(const File& file, std::string_view name)
{
    const auto found = std::find_if(file.sections.begin(), file.sections.end(), [&](const Section& section) {
        return section.name == name;
    });
    if (found == file.sections.end()) {
        return std::nullopt;
    }
    return *found;
}

std::vector<Symbol> function_symbols(const File& file)
{
    std::vector<Symbol> functions;
    for (const auto& symbol : file.symbols) {
        if (symbol.type == SymbolType::Function) {
            functions.push_back(symbol);
        }
    }
    return functions;
}

std::optional<Symbol> find_symbol(const File& file, std::string_view name)
{
    const auto found = std::find_if(file.symbols.begin(), file.symbols.end(), [&](const Symbol& symbol) {
        return symbol.name == name || maybe_demangle(symbol.name) == name;
    });
    if (found == file.symbols.end()) {
        return std::nullopt;
    }
    return *found;
}

std::optional<SectionBytes> section_bytes(const File& file, const Section& section)
{
    if (section.type == sht_nobits) {
        return std::nullopt;
    }
    if (!range_within(section.offset, section.size, file.image.size())) {
        return std::nullopt;
    }
    const auto begin = file.image.begin() + static_cast<std::ptrdiff_t>(section.offset);
    const auto end = begin + static_cast<std::ptrdiff_t>(section.size);
    return SectionBytes{section.address, begin, end};
}

} // namespace roe::elf
