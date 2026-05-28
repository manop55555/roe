// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "roe/pe.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <unordered_map>
#include <utility>

namespace roe::pe {
namespace {

constexpr std::uint16_t pe_machine_i386 = 0x014cU;
constexpr std::uint16_t pe_machine_amd64 = 0x8664U;
constexpr std::uint16_t pe_machine_arm64 = 0xaa64U;
constexpr std::uint16_t pe_machine_armnt = 0x01c4U;

constexpr std::uint16_t opt_magic_pe32 = 0x010bU;
constexpr std::uint16_t opt_magic_pe32_plus = 0x020bU;

constexpr std::uint32_t scn_cnt_code = 0x00000020U;
constexpr std::uint32_t scn_mem_execute = 0x20000000U;
constexpr std::uint32_t scn_mem_read = 0x40000000U;
constexpr std::uint32_t scn_mem_write = 0x80000000U;

constexpr std::uint16_t file_dll = 0x2000U;

Error make_error(ErrorCode code, std::string message)
{
    return Error{code, std::move(message), 0, false};
}

// PE is little-endian. Bounds-checked reader over the whole image.
class Reader {
public:
    explicit Reader(const std::vector<std::uint8_t>& bytes) noexcept : bytes_(bytes) {}

    [[nodiscard]] bool ok() const noexcept { return ok_; }

    std::uint16_t u16(std::size_t off) noexcept
    {
        if (off + 2 > bytes_.size()) {
            ok_ = false;
            return 0;
        }
        return static_cast<std::uint16_t>(bytes_[off] | (bytes_[off + 1] << 8));
    }
    std::uint32_t u32(std::size_t off) noexcept
    {
        if (off + 4 > bytes_.size()) {
            ok_ = false;
            return 0;
        }
        const std::uint8_t* p = bytes_.data() + off;
        return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
               (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
    }
    std::uint64_t u64(std::size_t off) noexcept
    {
        if (off + 8 > bytes_.size()) {
            ok_ = false;
            return 0;
        }
        std::uint64_t v = 0;
        for (int i = 0; i < 8; ++i) {
            v |= static_cast<std::uint64_t>(bytes_[off + static_cast<std::size_t>(i)]) << (8 * i);
        }
        return v;
    }
    std::string fixed_string(std::size_t off, std::size_t n)
    {
        if (off + n > bytes_.size()) {
            ok_ = false;
            return {};
        }
        std::string out;
        for (std::size_t i = 0; i < n && bytes_[off + i] != 0; ++i) {
            out.push_back(static_cast<char>(bytes_[off + i]));
        }
        return out;
    }
    std::string c_string(std::size_t off)
    {
        std::string out;
        for (std::size_t i = off; i < bytes_.size() && bytes_[i] != 0 && out.size() < 4096; ++i) {
            out.push_back(static_cast<char>(bytes_[i]));
        }
        return out;
    }

private:
    const std::vector<std::uint8_t>& bytes_;
    bool ok_{true};
};

binary::Architecture map_machine(std::uint16_t machine) noexcept
{
    switch (machine) {
    case pe_machine_i386:
        return binary::Architecture::X86;
    case pe_machine_amd64:
        return binary::Architecture::X86_64;
    case pe_machine_arm64:
        return binary::Architecture::AArch64;
    case pe_machine_armnt:
        return binary::Architecture::ArmThumb;
    default:
        return binary::Architecture::Unknown;
    }
}

struct SectionMap {
    std::uint32_t va{0};
    std::uint32_t vsize{0};
    std::uint32_t raw{0};
    std::uint32_t rawsize{0};
};

// Translate a relative virtual address to a file offset using the section map.
bool rva_to_offset(const std::vector<SectionMap>& sections, std::uint32_t rva, std::size_t& out)
{
    for (const SectionMap& s : sections) {
        const std::uint32_t span = std::max(s.vsize, s.rawsize);
        if (rva >= s.va && rva < s.va + span) {
            const std::uint32_t delta = rva - s.va;
            if (delta < s.rawsize) {
                out = static_cast<std::size_t>(s.raw) + delta;
                return true;
            }
        }
    }
    return false;
}

// A malformed PE can claim enormous import/export tables; cap total work so a
// hostile file cannot force unbounded parsing (resource exhaustion). 65536 is
// roughly 10x the import/export count of the largest real-world binaries.
constexpr std::uint32_t kMaxParsedSymbols = 65536;

void parse_imports(Reader& reader, const std::vector<SectionMap>& sections, std::uint32_t import_rva,
    bool pe32_plus, binary::Object& object)
{
    std::size_t dir_off = 0;
    if (import_rva == 0 || !rva_to_offset(sections, import_rva, dir_off)) {
        return;
    }
    std::uint32_t budget = 0;
    for (std::uint32_t entry = 0; entry < 4096; ++entry) {
        const std::size_t base = dir_off + (static_cast<std::size_t>(entry) * 20U);
        const std::uint32_t ilt_rva = reader.u32(base);
        const std::uint32_t name_rva = reader.u32(base + 12);
        const std::uint32_t iat_rva = reader.u32(base + 16);
        if (!reader.ok() || (ilt_rva == 0 && name_rva == 0 && iat_rva == 0)) {
            break;
        }
        std::size_t name_off = 0;
        std::string dll = "?";
        if (rva_to_offset(sections, name_rva, name_off)) {
            dll = reader.c_string(name_off);
        }
        object.libraries.push_back(dll);

        const std::uint32_t thunk_rva = ilt_rva != 0 ? ilt_rva : iat_rva;
        std::size_t thunk_off = 0;
        if (thunk_rva == 0 || !rva_to_offset(sections, thunk_rva, thunk_off)) {
            continue;
        }
        const std::size_t thunk_size = pe32_plus ? 8U : 4U;
        for (std::uint32_t t = 0; t < 65536; ++t) {
            if (budget++ >= kMaxParsedSymbols) {
                return; // bound total work across all descriptors
            }
            const std::size_t to = thunk_off + (static_cast<std::size_t>(t) * thunk_size);
            const std::uint64_t thunk = pe32_plus ? reader.u64(to) : reader.u32(to);
            if (!reader.ok() || thunk == 0) {
                break;
            }
            const std::uint64_t ordinal_flag = pe32_plus ? (1ULL << 63) : (1ULL << 31);
            binary::Symbol symbol;
            symbol.object_index = object.index;
            symbol.bind = binary::SymbolBind::Imported;
            symbol.type = binary::SymbolType::Function;
            symbol.dynamic = true;
            symbol.library = dll;
            if ((thunk & ordinal_flag) != 0U) {
                symbol.name = "Ordinal#" + std::to_string(thunk & 0xffffU);
                symbol.raw_name = symbol.name;
            } else {
                std::size_t hint_off = 0;
                if (rva_to_offset(sections, static_cast<std::uint32_t>(thunk & 0x7fffffffU), hint_off)) {
                    symbol.name = reader.c_string(hint_off + 2); // skip 2-byte hint
                    symbol.raw_name = symbol.name;
                }
            }
            if (!symbol.name.empty()) {
                object.symbols.push_back(std::move(symbol));
            }
        }
    }
}

void parse_exports(Reader& reader, const std::vector<SectionMap>& sections, std::uint32_t export_rva,
    binary::Object& object)
{
    std::size_t dir_off = 0;
    if (export_rva == 0 || !rva_to_offset(sections, export_rva, dir_off)) {
        return;
    }
    const std::uint32_t num_names = reader.u32(dir_off + 24);
    const std::uint32_t names_rva = reader.u32(dir_off + 32);
    std::size_t names_off = 0;
    if (num_names == 0 || num_names > kMaxParsedSymbols || !rva_to_offset(sections, names_rva, names_off)) {
        return;
    }
    for (std::uint32_t i = 0; i < num_names; ++i) {
        const std::uint32_t name_rva = reader.u32(names_off + (static_cast<std::size_t>(i) * 4U));
        std::size_t name_off = 0;
        if (!reader.ok() || !rva_to_offset(sections, name_rva, name_off)) {
            break;
        }
        binary::Symbol symbol;
        symbol.name = reader.c_string(name_off);
        symbol.raw_name = symbol.name;
        symbol.object_index = object.index;
        symbol.bind = binary::SymbolBind::Exported;
        symbol.type = binary::SymbolType::Function;
        symbol.defined = true;
        symbol.dynamic = true;
        if (!symbol.name.empty()) {
            object.symbols.push_back(std::move(symbol));
        }
    }
}

// COFF symbol classification: a symbol whose complex (derived) type is FUNCTION.
constexpr std::uint16_t coff_sym_dtype_function = 0x20U; // IMAGE_SYM_DTYPE_FUNCTION (2) << 4
constexpr std::uint16_t coff_sym_class_external = 2U;    // IMAGE_SYM_CLASS_EXTERNAL

// Read the COFF symbol table (PointerToSymbolTable / NumberOfSymbols in the COFF
// header) into normalized function symbols, resolving long names through the
// trailing string table. The table is optional: linkers commonly strip it
// (IMAGE_FILE_LOCAL_SYMS_STRIPPED), in which case the object is marked stripped
// and callers fall back to the export table. mingw emits section-relative symbol
// Values, so address = section.address + value (verified against objdump: e.g.
// main at .text+0x477). NumberOfSymbols is attacker-controlled, so it is clamped
// before any offset arithmetic and every read stays bounds-checked.
void parse_coff_symbols(Reader& reader, const std::vector<std::uint8_t>& bytes, std::size_t coff, binary::Object& object)
{
    const std::uint32_t sym_ptr = reader.u32(coff + 8);
    const std::uint32_t raw_count = reader.u32(coff + 12);
    if (!reader.ok() || sym_ptr == 0 || raw_count == 0) {
        object.stripped = true; // no COFF symbol table (commonly stripped)
        return;
    }
    const std::uint32_t count = std::min(raw_count, kMaxParsedSymbols);
    const std::size_t symtab = static_cast<std::size_t>(sym_ptr);
    const std::size_t symtab_end = symtab + (static_cast<std::size_t>(count) * 18U);
    if (symtab_end > bytes.size()) {
        object.stripped = true; // truncated or implausible symbol table
        return;
    }
    const std::size_t strtab = symtab_end; // string table immediately follows the symbols

    // Index existing exports by name so a function that is both exported and present
    // in the COFF table fills the export's missing address instead of duplicating it.
    std::unordered_map<std::string, std::size_t> export_index;
    for (std::size_t k = 0; k < object.symbols.size(); ++k) {
        if (object.symbols[k].bind == binary::SymbolBind::Exported) {
            export_index.emplace(object.symbols[k].name, k);
        }
    }

    for (std::uint32_t i = 0; i < count;) {
        const std::size_t off = symtab + (static_cast<std::size_t>(i) * 18U);
        const std::uint32_t name_inline = reader.u32(off);
        const std::uint32_t value = reader.u32(off + 8);
        const std::int16_t secnum = static_cast<std::int16_t>(reader.u16(off + 12));
        const std::uint16_t type = reader.u16(off + 14);
        const std::uint16_t class_aux = reader.u16(off + 16); // storage class | (aux count << 8)
        if (!reader.ok()) {
            break;
        }
        const std::uint8_t storage = static_cast<std::uint8_t>(class_aux & 0xFFU);
        const std::uint8_t aux = static_cast<std::uint8_t>((class_aux >> 8) & 0xFFU);
        i += 1U + static_cast<std::uint32_t>(aux); // step over auxiliary records

        // Only defined functions anchored to a real section become function symbols.
        if (type != coff_sym_dtype_function || secnum < 1) {
            continue;
        }
        const std::size_t section_index = static_cast<std::size_t>(secnum) - 1U;
        if (section_index >= object.sections.size()) {
            continue;
        }
        std::string name;
        if (name_inline == 0U) {
            const std::uint32_t str_off = reader.u32(off + 4);
            name = reader.c_string(strtab + static_cast<std::size_t>(str_off));
        } else {
            name = reader.fixed_string(off, 8);
        }
        if (name.empty()) {
            continue;
        }
        const std::uint64_t address = object.sections[section_index].address + value;

        if (const auto existing = export_index.find(name); existing != export_index.end()) {
            binary::Symbol& exported = object.symbols[existing->second];
            if (exported.address == 0U) {
                exported.address = address;
                exported.section_index = static_cast<std::uint32_t>(section_index);
                exported.defined = true;
            }
            continue;
        }

        binary::Symbol symbol;
        symbol.object_index = object.index;
        symbol.name = name;
        symbol.raw_name = name;
        symbol.address = address;
        symbol.section_index = static_cast<std::uint32_t>(section_index);
        symbol.bind = storage == coff_sym_class_external ? binary::SymbolBind::Global : binary::SymbolBind::Local;
        symbol.type = binary::SymbolType::Function;
        symbol.defined = true;
        object.symbols.push_back(std::move(symbol));
    }
}

} // namespace

Result<File> parse_bytes(std::string source_name, std::vector<std::uint8_t> bytes)
{
    if (bytes.size() < 0x40 || bytes[0] != 'M' || bytes[1] != 'Z') {
        return Result<File>::err(make_error(ErrorCode::UnsupportedFormat, "not a PE file (missing MZ header)"));
    }
    Reader reader(bytes);
    const std::uint32_t pe_off = reader.u32(0x3c);
    if (pe_off + 24 > bytes.size() || reader.u32(pe_off) != 0x00004550U) {
        return Result<File>::err(make_error(ErrorCode::MalformedInput, "invalid PE signature"));
    }

    const std::size_t coff = pe_off + 4;
    const std::uint16_t machine = reader.u16(coff);
    const std::uint16_t num_sections = reader.u16(coff + 2);
    const std::uint16_t opt_size = reader.u16(coff + 16);
    const std::uint16_t characteristics = reader.u16(coff + 18);
    const std::size_t opt = coff + 20;

    const std::uint16_t opt_magic = reader.u16(opt);
    const bool pe32_plus = opt_magic == opt_magic_pe32_plus;
    if (opt_magic != opt_magic_pe32 && opt_magic != opt_magic_pe32_plus) {
        return Result<File>::err(make_error(ErrorCode::MalformedInput, "unknown PE optional header magic"));
    }

    const std::uint32_t entry_rva = reader.u32(opt + 16);
    const std::uint64_t image_base = pe32_plus ? reader.u64(opt + 24) : reader.u32(opt + 28);
    const std::size_t datadir_off = opt + (pe32_plus ? 112U : 96U);
    const std::uint32_t num_dirs = reader.u32(opt + (pe32_plus ? 108U : 92U));

    binary::Object object;
    object.index = 0;
    object.format = binary::Format::PeCoff;
    object.architecture = map_machine(machine);
    object.address_width = pe32_plus ? binary::AddressWidth::Bits64 : binary::AddressWidth::Bits32;
    object.endianness = binary::Endianness::Little;
    object.kind = (characteristics & file_dll) != 0U ? binary::ObjectKind::SharedLibrary : binary::ObjectKind::Executable;
    object.entry = image_base + entry_rva;

    if (num_sections > 4096) {
        return Result<File>::err(make_error(ErrorCode::MalformedInput, "implausible PE section count"));
    }
    const std::size_t sect_table = opt + opt_size;
    std::vector<SectionMap> maps;
    for (std::uint16_t i = 0; i < num_sections; ++i) {
        const std::size_t so = sect_table + (static_cast<std::size_t>(i) * 40U);
        if (so + 40 > bytes.size()) {
            break;
        }
        binary::Section section;
        section.name = reader.fixed_string(so, 8);
        section.object_index = 0;
        section.index = i;
        const std::uint32_t vsize = reader.u32(so + 8);
        const std::uint32_t va = reader.u32(so + 12);
        const std::uint32_t rawsize = reader.u32(so + 16);
        const std::uint32_t raw = reader.u32(so + 20);
        const std::uint32_t flags = reader.u32(so + 36);
        section.address = image_base + va;
        section.offset = raw;
        section.size = rawsize;
        section.readable = (flags & scn_mem_read) != 0U;
        section.writable = (flags & scn_mem_write) != 0U;
        section.executable = (flags & (scn_mem_execute | scn_cnt_code)) != 0U;
        if (section.executable) {
            section.kind = binary::SectionKind::Code;
        } else if (!section.writable) {
            section.kind = binary::SectionKind::ReadOnlyData;
        } else {
            section.kind = binary::SectionKind::Data;
        }
        object.sections.push_back(std::move(section));
        maps.push_back(SectionMap{va, vsize, raw, rawsize});
    }

    // Data directories become segments for --segments.
    static const std::array<const char*, 16> dir_names = {"export", "import", "resource", "exception",
        "certificate", "basereloc", "debug", "architecture", "globalptr", "tls", "load_config", "bound_import",
        "iat", "delay_import", "clr_runtime", "reserved"};
    const std::uint32_t dirs = std::min<std::uint32_t>(num_dirs, 16U);
    std::uint32_t import_rva = 0;
    std::uint32_t export_rva = 0;
    for (std::uint32_t i = 0; i < dirs; ++i) {
        const std::uint32_t rva = reader.u32(datadir_off + (static_cast<std::size_t>(i) * 8U));
        const std::uint32_t size = reader.u32(datadir_off + (static_cast<std::size_t>(i) * 8U) + 4U);
        if (rva == 0 && size == 0) {
            continue;
        }
        binary::Segment segment;
        segment.name = dir_names[i];
        segment.address = image_base + rva;
        segment.size = size;
        segment.detail = "data directory";
        object.segments.push_back(std::move(segment));
        if (i == 0) {
            export_rva = rva;
        } else if (i == 1) {
            import_rva = rva;
        }
    }

    parse_imports(reader, maps, import_rva, pe32_plus, object);
    parse_exports(reader, maps, export_rva, object);
    parse_coff_symbols(reader, bytes, coff, object);

    File file;
    file.view.source_name = std::move(source_name);
    file.view.format = binary::Format::PeCoff;
    const std::size_t prefix = std::min<std::size_t>(16U, bytes.size());
    file.view.first_bytes.assign(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(prefix));
    file.view.objects.push_back(std::move(object));
    file.image = std::move(bytes);
    return Result<File>::ok(std::move(file));
}

Result<File> parse_file(const std::filesystem::path& path)
{
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        return Result<File>::err(make_error(ErrorCode::FileIo, "failed to open file: " + path.string()));
    }
    std::vector<std::uint8_t> bytes;
    stream.unsetf(std::ios::skipws);
    bytes.assign(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
    return parse_bytes(path.string(), std::move(bytes));
}

namespace {
class PeBinaryFile final : public binary::BinaryFile {
public:
    PeBinaryFile(binary::FileView view, std::vector<std::uint8_t> image)
        : view_(std::move(view)), image_(std::move(image))
    {
    }
    [[nodiscard]] const binary::FileView& view() const noexcept override { return view_; }
    [[nodiscard]] Result<binary::SectionBytes> section_bytes(const binary::Section& section) const override
    {
        if (section.offset > image_.size() || section.size > image_.size() - section.offset) {
            return Result<binary::SectionBytes>::ok(
                binary::SectionBytes{section.object_index, section.name, section.address, {}});
        }
        const auto first = image_.begin() + static_cast<std::ptrdiff_t>(section.offset);
        const auto last = first + static_cast<std::ptrdiff_t>(section.size);
        return Result<binary::SectionBytes>::ok(
            binary::SectionBytes{section.object_index, section.name, section.address, {first, last}});
    }

private:
    binary::FileView view_;
    std::vector<std::uint8_t> image_;
};
} // namespace

Result<std::unique_ptr<binary::BinaryFile>> open_bytes(std::string source_name, std::vector<std::uint8_t> bytes)
{
    Result<File> parsed = parse_bytes(std::move(source_name), std::move(bytes));
    if (!parsed) {
        return Result<std::unique_ptr<binary::BinaryFile>>::err(std::move(parsed).error());
    }
    File file = std::move(parsed).value();
    return Result<std::unique_ptr<binary::BinaryFile>>::ok(
        std::make_unique<PeBinaryFile>(std::move(file.view), std::move(file.image)));
}

Result<std::unique_ptr<binary::BinaryFile>> open_file(const std::filesystem::path& path)
{
    Result<File> parsed = parse_file(path);
    if (!parsed) {
        return Result<std::unique_ptr<binary::BinaryFile>>::err(std::move(parsed).error());
    }
    File file = std::move(parsed).value();
    return Result<std::unique_ptr<binary::BinaryFile>>::ok(
        std::make_unique<PeBinaryFile>(std::move(file.view), std::move(file.image)));
}

} // namespace roe::pe
