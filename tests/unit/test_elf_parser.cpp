#include "roe/elf.hpp"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#if __has_include(<catch2/catch_test_macros.hpp>)
#include <catch2/catch_test_macros.hpp>
#define ROE_ELF_USE_CATCH 1
#else
#define ROE_ELF_USE_CATCH 0
#endif

namespace {

void append_u8(std::vector<std::uint8_t>& bytes, std::uint8_t value)
{
    bytes.push_back(value);
}

void append_le16(std::vector<std::uint8_t>& bytes, std::uint16_t value)
{
    bytes.push_back(static_cast<std::uint8_t>(value & 0xffU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
}

void append_le32(std::vector<std::uint8_t>& bytes, std::uint32_t value)
{
    for (std::uint32_t shift = 0; shift < 32U; shift += 8U) {
        bytes.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffU));
    }
}

void append_le64(std::vector<std::uint8_t>& bytes, std::uint64_t value)
{
    for (std::uint32_t shift = 0; shift < 64U; shift += 8U) {
        bytes.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffU));
    }
}

void put_le16(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint16_t value)
{
    bytes[offset] = static_cast<std::uint8_t>(value & 0xffU);
    bytes[offset + 1U] = static_cast<std::uint8_t>((value >> 8U) & 0xffU);
}

void put_le32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value)
{
    for (std::uint32_t shift = 0; shift < 32U; shift += 8U) {
        bytes[offset + static_cast<std::size_t>(shift / 8U)] = static_cast<std::uint8_t>((value >> shift) & 0xffU);
    }
}

void put_le64(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint64_t value)
{
    for (std::uint32_t shift = 0; shift < 64U; shift += 8U) {
        bytes[offset + static_cast<std::size_t>(shift / 8U)] = static_cast<std::uint8_t>((value >> shift) & 0xffU);
    }
}

void put_be16(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint16_t value)
{
    bytes[offset] = static_cast<std::uint8_t>((value >> 8U) & 0xffU);
    bytes[offset + 1U] = static_cast<std::uint8_t>(value & 0xffU);
}

void put_be32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value)
{
    bytes[offset] = static_cast<std::uint8_t>((value >> 24U) & 0xffU);
    bytes[offset + 1U] = static_cast<std::uint8_t>((value >> 16U) & 0xffU);
    bytes[offset + 2U] = static_cast<std::uint8_t>((value >> 8U) & 0xffU);
    bytes[offset + 3U] = static_cast<std::uint8_t>(value & 0xffU);
}

void put_be64(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint64_t value)
{
    for (std::uint32_t i = 0; i < 8U; ++i) {
        const std::uint32_t shift = 56U - (i * 8U);
        bytes[offset + i] = static_cast<std::uint8_t>((value >> shift) & 0xffU);
    }
}

void align_to(std::vector<std::uint8_t>& bytes, std::size_t alignment)
{
    while ((bytes.size() % alignment) != 0U) {
        bytes.push_back(0);
    }
}

std::uint32_t add_string(std::vector<std::uint8_t>& table, const std::string& value)
{
    const auto offset = static_cast<std::uint32_t>(table.size());
    table.insert(table.end(), value.begin(), value.end());
    table.push_back(0);
    return offset;
}

void append_elf64_symbol(
    std::vector<std::uint8_t>& bytes,
    std::uint32_t name,
    std::uint8_t info,
    std::uint16_t section,
    std::uint64_t value,
    std::uint64_t size)
{
    append_le32(bytes, name);
    append_u8(bytes, info);
    append_u8(bytes, 0);
    append_le16(bytes, section);
    append_le64(bytes, value);
    append_le64(bytes, size);
}

void append_elf64_section(
    std::vector<std::uint8_t>& bytes,
    std::uint32_t name,
    std::uint32_t type,
    std::uint64_t flags,
    std::uint64_t address,
    std::uint64_t offset,
    std::uint64_t size,
    std::uint32_t link,
    std::uint32_t info,
    std::uint64_t alignment,
    std::uint64_t entry_size)
{
    append_le32(bytes, name);
    append_le32(bytes, type);
    append_le64(bytes, flags);
    append_le64(bytes, address);
    append_le64(bytes, offset);
    append_le64(bytes, size);
    append_le32(bytes, link);
    append_le32(bytes, info);
    append_le64(bytes, alignment);
    append_le64(bytes, entry_size);
}

std::vector<std::uint8_t> make_elf64_little_object()
{
    std::vector<std::uint8_t> bytes(64U, 0);
    bytes[0] = 0x7fU;
    bytes[1] = 'E';
    bytes[2] = 'L';
    bytes[3] = 'F';
    bytes[4] = 2U;
    bytes[5] = 1U;
    bytes[6] = 1U;
    put_le16(bytes, 16U, 1U);
    put_le16(bytes, 18U, 62U);
    put_le32(bytes, 20U, 1U);
    put_le16(bytes, 52U, 64U);
    put_le16(bytes, 54U, 56U);
    put_le16(bytes, 58U, 64U);
    put_le16(bytes, 60U, 6U);
    put_le16(bytes, 62U, 5U);

    const std::vector<std::uint8_t> text{0x55U, 0x48U, 0x89U, 0xe5U, 0xc3U};
    const auto text_offset = static_cast<std::uint64_t>(bytes.size());
    bytes.insert(bytes.end(), text.begin(), text.end());

    std::vector<std::uint8_t> strtab{0};
    const auto func_name = add_string(strtab, "func");
    const auto ext_name = add_string(strtab, "ext");
    const auto strtab_offset = static_cast<std::uint64_t>(bytes.size());
    bytes.insert(bytes.end(), strtab.begin(), strtab.end());

    align_to(bytes, 8U);
    const auto symtab_offset = static_cast<std::uint64_t>(bytes.size());
    append_elf64_symbol(bytes, 0U, 0U, 0U, 0U, 0U);
    append_elf64_symbol(bytes, func_name, 0x12U, 1U, 0U, static_cast<std::uint64_t>(text.size()));
    append_elf64_symbol(bytes, ext_name, 0x10U, 0U, 0U, 0U);

    align_to(bytes, 8U);
    const auto rela_offset = static_cast<std::uint64_t>(bytes.size());
    append_le64(bytes, 1U);
    append_le64(bytes, (2ULL << 32U) | 4ULL);
    append_le64(bytes, 0xfffffffffffffffcULL);

    std::vector<std::uint8_t> shstr{0};
    const auto sh_text = add_string(shstr, ".text");
    const auto sh_symtab = add_string(shstr, ".symtab");
    const auto sh_strtab = add_string(shstr, ".strtab");
    const auto sh_rela_text = add_string(shstr, ".rela.text");
    const auto sh_shstrtab = add_string(shstr, ".shstrtab");
    const auto shstr_offset = static_cast<std::uint64_t>(bytes.size());
    bytes.insert(bytes.end(), shstr.begin(), shstr.end());

    align_to(bytes, 8U);
    const auto section_header_offset = static_cast<std::uint64_t>(bytes.size());
    append_elf64_section(bytes, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U);
    append_elf64_section(bytes, sh_text, 1U, 0x6U, 0U, text_offset, static_cast<std::uint64_t>(text.size()), 0U, 0U, 1U, 0U);
    append_elf64_section(bytes, sh_symtab, 2U, 0U, 0U, symtab_offset, 72U, 3U, 1U, 8U, 24U);
    append_elf64_section(bytes, sh_strtab, 3U, 0U, 0U, strtab_offset, static_cast<std::uint64_t>(strtab.size()), 0U, 0U, 1U, 0U);
    append_elf64_section(bytes, sh_rela_text, 4U, 0U, 0U, rela_offset, 24U, 2U, 1U, 8U, 24U);
    append_elf64_section(bytes, sh_shstrtab, 3U, 0U, 0U, shstr_offset, static_cast<std::uint64_t>(shstr.size()), 0U, 0U, 1U, 0U);
    put_le64(bytes, 40U, section_header_offset);

    return bytes;
}

std::vector<std::uint8_t> make_elf32_big_minimal()
{
    std::vector<std::uint8_t> bytes(52U, 0);
    bytes[0] = 0x7fU;
    bytes[1] = 'E';
    bytes[2] = 'L';
    bytes[3] = 'F';
    bytes[4] = 1U;
    bytes[5] = 2U;
    bytes[6] = 1U;
    put_be16(bytes, 16U, 2U);
    put_be16(bytes, 18U, 3U);
    put_be32(bytes, 20U, 1U);
    put_be32(bytes, 32U, 52U);
    put_be16(bytes, 40U, 52U);
    put_be16(bytes, 42U, 32U);
    put_be16(bytes, 46U, 40U);
    put_be16(bytes, 48U, 1U);
    put_be16(bytes, 50U, 0U);
    bytes.resize(92U, 0);
    return bytes;
}

std::vector<std::uint8_t> make_elf64_big_minimal()
{
    std::vector<std::uint8_t> bytes(64U, 0);
    bytes[0] = 0x7fU;
    bytes[1] = 'E';
    bytes[2] = 'L';
    bytes[3] = 'F';
    bytes[4] = 2U;
    bytes[5] = 2U;
    bytes[6] = 1U;
    put_be16(bytes, 16U, 3U);
    put_be16(bytes, 18U, 183U);
    put_be32(bytes, 20U, 1U);
    put_be64(bytes, 40U, 64U);
    put_be16(bytes, 52U, 64U);
    put_be16(bytes, 54U, 56U);
    put_be16(bytes, 58U, 64U);
    put_be16(bytes, 60U, 1U);
    put_be16(bytes, 62U, 0U);
    bytes.resize(128U, 0);
    return bytes;
}

bool test_valid_elf64_object()
{
    auto parsed = roe::elf::parse_bytes("synthetic64.o", make_elf64_little_object());
    if (!parsed) {
        std::cerr << parsed.error().message << '\n';
        return false;
    }

    const auto& file = parsed.value();
    if (file.elf_class != roe::elf::Class::Elf64 || file.endianness != roe::elf::Endianness::Little) {
        return false;
    }
    if (file.file_type != roe::elf::FileType::Relocatable || file.machine != roe::elf::Machine::X86_64) {
        return false;
    }
    if (file.sections.size() != 6U || file.symbols.size() != 3U || file.relocations.size() != 1U) {
        return false;
    }
    const auto text = roe::elf::find_section(file, ".text");
    if (!text || !text->executable) {
        return false;
    }
    const auto text_bytes = roe::elf::section_bytes(file, *text);
    if (!text_bytes || static_cast<std::size_t>(text_bytes->end - text_bytes->begin) != 5U) {
        return false;
    }
    const auto functions = roe::elf::function_symbols(file);
    if (functions.size() != 1U || functions[0].name != "func" || functions[0].size != 5U) {
        return false;
    }
    const auto symbol = roe::elf::find_symbol(file, "func");
    if (!symbol || !symbol->defined) {
        return false;
    }
    const auto& relocation = file.relocations[0];
    return relocation.section_name == ".rela.text" && relocation.offset == 1U && relocation.symbol_index == 2U &&
        relocation.symbol_name == "ext" && relocation.has_addend && relocation.addend == -4;
}

bool test_valid_elf32_big_endian()
{
    auto parsed = roe::elf::parse_bytes("synthetic32", make_elf32_big_minimal());
    if (!parsed) {
        std::cerr << parsed.error().message << '\n';
        return false;
    }
    const auto& file = parsed.value();
    return file.elf_class == roe::elf::Class::Elf32 && file.endianness == roe::elf::Endianness::Big &&
        file.file_type == roe::elf::FileType::Executable && file.machine == roe::elf::Machine::X86 && file.sections.size() == 1U &&
        file.stripped;
}

bool test_valid_elf64_big_endian()
{
    auto parsed = roe::elf::parse_bytes("synthetic64be.so", make_elf64_big_minimal());
    if (!parsed) {
        std::cerr << parsed.error().message << '\n';
        return false;
    }
    const auto& file = parsed.value();
    return file.elf_class == roe::elf::Class::Elf64 && file.endianness == roe::elf::Endianness::Big &&
        file.file_type == roe::elf::FileType::SharedObject && file.machine == roe::elf::Machine::AArch64 &&
        file.sections.size() == 1U && file.stripped;
}

bool test_malformed_inputs()
{
    auto short_file = roe::elf::parse_bytes("short", std::vector<std::uint8_t>{0x7fU, 'E', 'L'});
    if (short_file || short_file.error().code != roe::ErrorCode::MalformedInput) {
        return false;
    }

    auto not_elf = roe::elf::parse_bytes("text", std::vector<std::uint8_t>{'n', 'o', 'p', 'e'});
    if (not_elf || not_elf.error().code != roe::ErrorCode::MalformedInput) {
        return false;
    }

    std::vector<std::uint8_t> bad_magic(16U, 0);
    auto bad_magic_result = roe::elf::parse_bytes("bad-magic", std::move(bad_magic));
    if (bad_magic_result || bad_magic_result.error().code != roe::ErrorCode::UnsupportedFormat) {
        return false;
    }

    auto truncated = make_elf64_little_object();
    truncated.resize(truncated.size() - 12U);
    auto parsed_truncated = roe::elf::parse_bytes("truncated", std::move(truncated));
    if (parsed_truncated || parsed_truncated.error().code != roe::ErrorCode::MalformedInput) {
        return false;
    }

    auto bad_section_name = make_elf64_little_object();
    const auto section_header_offset = static_cast<std::size_t>(
        bad_section_name[40U] | (static_cast<std::uint64_t>(bad_section_name[41U]) << 8U) |
        (static_cast<std::uint64_t>(bad_section_name[42U]) << 16U) |
        (static_cast<std::uint64_t>(bad_section_name[43U]) << 24U));
    put_le32(bad_section_name, section_header_offset + 64U, 0xffffU);
    auto parsed_bad_name = roe::elf::parse_bytes("bad-section-name", std::move(bad_section_name));
    return !parsed_bad_name && parsed_bad_name.error().code == roe::ErrorCode::MalformedInput;
}

} // namespace

#if ROE_ELF_USE_CATCH
TEST_CASE("test_elf_valid_elf64_object")
{
    REQUIRE(test_valid_elf64_object());
}

TEST_CASE("test_elf_valid_elf32_big_endian")
{
    REQUIRE(test_valid_elf32_big_endian());
}

TEST_CASE("test_elf_valid_elf64_big_endian")
{
    REQUIRE(test_valid_elf64_big_endian());
}

TEST_CASE("test_elf_malformed_inputs")
{
    REQUIRE(test_malformed_inputs());
}
#else
int main()
{
    if (!test_valid_elf64_object()) {
        std::cerr << "test_elf_valid_elf64_object failed\n";
        return EXIT_FAILURE;
    }
    if (!test_valid_elf32_big_endian()) {
        std::cerr << "test_elf_valid_elf32_big_endian failed\n";
        return EXIT_FAILURE;
    }
    if (!test_valid_elf64_big_endian()) {
        std::cerr << "test_elf_valid_elf64_big_endian failed\n";
        return EXIT_FAILURE;
    }
    if (!test_malformed_inputs()) {
        std::cerr << "test_elf_malformed_inputs failed\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
#endif
