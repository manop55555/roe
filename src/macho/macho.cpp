// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The roe Authors

#include "roe/macho.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <utility>

namespace roe::macho {
namespace {

constexpr std::uint32_t mh_magic = 0xfeedfaceU;
constexpr std::uint32_t mh_cigam = 0xcefaedfeU;
constexpr std::uint32_t mh_magic_64 = 0xfeedfacfU;
constexpr std::uint32_t mh_cigam_64 = 0xcffaedfeU;
constexpr std::uint32_t fat_magic = 0xcafebabeU;
constexpr std::uint32_t fat_cigam = 0xbebafecaU;
constexpr std::uint32_t fat_magic_64 = 0xcafebabfU;
constexpr std::uint32_t fat_cigam_64 = 0xbfbafecaU;

constexpr std::uint32_t cpu_arch_abi64 = 0x01000000U;
constexpr std::uint32_t cpu_type_x86 = 7U;
constexpr std::uint32_t cpu_type_arm = 12U;

constexpr std::uint32_t lc_segment = 0x1U;
constexpr std::uint32_t lc_symtab = 0x2U;
constexpr std::uint32_t lc_segment_64 = 0x19U;
constexpr std::uint32_t lc_main = 0x80000028U;
constexpr std::uint32_t lc_load_dylib = 0xcU;
constexpr std::uint32_t lc_load_weak_dylib = 0x80000018U;
constexpr std::uint32_t lc_reexport_dylib = 0x8000001fU;

constexpr std::uint8_t n_stab = 0xe0U;
constexpr std::uint8_t n_type_mask = 0x0eU;
constexpr std::uint8_t n_ext = 0x01U;
constexpr std::uint8_t n_undf = 0x0U;
constexpr std::uint8_t n_sect = 0xeU;

constexpr std::uint32_t vm_prot_read = 0x1U;
constexpr std::uint32_t vm_prot_write = 0x2U;
constexpr std::uint32_t vm_prot_execute = 0x4U;

Error make_error(ErrorCode code, std::string message)
{
    return Error{code, std::move(message), 0, false};
}

class Reader {
public:
    Reader(const std::vector<std::uint8_t>& bytes, bool big_endian) noexcept : bytes_(bytes), big_(big_endian) {}

    [[nodiscard]] bool ok() const noexcept { return ok_; }
    [[nodiscard]] std::size_t size() const noexcept { return bytes_.size(); }

    std::uint32_t u32(std::size_t offset) noexcept
    {
        if (offset + 4 > bytes_.size()) {
            ok_ = false;
            return 0;
        }
        const std::uint8_t* p = bytes_.data() + offset;
        if (big_) {
            return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
                   (static_cast<std::uint32_t>(p[2]) << 8) | p[3];
        }
        return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
               (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
    }

    std::uint64_t u64(std::size_t offset) noexcept
    {
        if (offset + 8 > bytes_.size()) {
            ok_ = false;
            return 0;
        }
        const std::uint8_t* p = bytes_.data() + offset;
        std::uint64_t value = 0;
        if (big_) {
            for (int i = 0; i < 8; ++i) {
                value = (value << 8) | p[i];
            }
        } else {
            for (int i = 0; i < 8; ++i) {
                value |= static_cast<std::uint64_t>(p[i]) << (8 * i);
            }
        }
        return value;
    }

    std::uint8_t u8(std::size_t offset) noexcept
    {
        if (offset >= bytes_.size()) {
            ok_ = false;
            return 0;
        }
        return bytes_[offset];
    }

    std::uint16_t u16(std::size_t offset) noexcept
    {
        if (offset + 2 > bytes_.size()) {
            ok_ = false;
            return 0;
        }
        const std::uint8_t* p = bytes_.data() + offset;
        return big_ ? static_cast<std::uint16_t>((p[0] << 8) | p[1])
                    : static_cast<std::uint16_t>(p[0] | (p[1] << 8));
    }

    std::string fixed_string(std::size_t offset, std::size_t max_len)
    {
        if (offset + max_len > bytes_.size()) {
            ok_ = false;
            return {};
        }
        std::string out;
        for (std::size_t i = 0; i < max_len && bytes_[offset + i] != 0; ++i) {
            out.push_back(static_cast<char>(bytes_[offset + i]));
        }
        return out;
    }

    std::string c_string(std::size_t offset)
    {
        std::string out;
        for (std::size_t i = offset; i < bytes_.size() && bytes_[i] != 0; ++i) {
            out.push_back(static_cast<char>(bytes_[i]));
        }
        return out;
    }

private:
    const std::vector<std::uint8_t>& bytes_;
    bool big_{false};
    bool ok_{true};
};

binary::Architecture map_arch(std::uint32_t cputype) noexcept
{
    const bool is64 = (cputype & cpu_arch_abi64) != 0U;
    const std::uint32_t base = cputype & ~cpu_arch_abi64;
    if (base == cpu_type_x86) {
        return is64 ? binary::Architecture::X86_64 : binary::Architecture::X86;
    }
    if (base == cpu_type_arm) {
        return is64 ? binary::Architecture::AArch64 : binary::Architecture::Arm;
    }
    return binary::Architecture::Unknown;
}

void extract_strings(const std::vector<std::uint8_t>& image, binary::Object& object)
{
    for (const binary::Section& section : object.sections) {
        const bool stringy = section.kind == binary::SectionKind::CString ||
                             section.kind == binary::SectionKind::ReadOnlyData;
        // Overflow-safe range check: section.offset + section.size must not exceed the image.
        if (!stringy || section.offset == 0 || section.offset > image.size() ||
            section.size > image.size() - section.offset) {
            continue;
        }
        std::string current;
        std::uint64_t start = 0;
        for (std::uint64_t i = 0; i < section.size; ++i) {
            const std::uint8_t byte = image[static_cast<std::size_t>(section.offset + i)];
            if (byte == 0) {
                if (current.size() >= 2) {
                    object.strings.push_back({object.index, section.address + start, current.size(), current});
                }
                current.clear();
            } else if ((byte >= 0x20 && byte < 0x7f) || byte == '\t' || byte == '\n') {
                if (current.empty()) {
                    start = i;
                }
                current.push_back(static_cast<char>(byte));
            } else {
                current.clear();
            }
        }
    }
}

// Parse one thin Mach-O image into an Object. Returns false (via Result) on malformed input.
Result<binary::Object> parse_thin(const std::vector<std::uint8_t>& bytes, std::size_t object_index)
{
    if (bytes.size() < 4) {
        return Result<binary::Object>::err(make_error(ErrorCode::MalformedInput, "Mach-O image too small"));
    }
    const std::uint32_t magic = (static_cast<std::uint32_t>(bytes[0])) | (static_cast<std::uint32_t>(bytes[1]) << 8) |
                                (static_cast<std::uint32_t>(bytes[2]) << 16) | (static_cast<std::uint32_t>(bytes[3]) << 24);
    bool is64 = false;
    bool big = false;
    if (magic == mh_magic_64) {
        is64 = true;
    } else if (magic == mh_cigam_64) {
        is64 = true;
        big = true;
    } else if (magic == mh_magic) {
        is64 = false;
    } else if (magic == mh_cigam) {
        big = true;
    } else {
        return Result<binary::Object>::err(make_error(ErrorCode::UnsupportedFormat, "not a thin Mach-O image"));
    }

    Reader reader(bytes, big);
    const std::uint32_t cputype = reader.u32(4);
    const std::uint32_t filetype = reader.u32(12);
    const std::uint32_t ncmds = reader.u32(16);
    const std::size_t header_size = is64 ? 32U : 28U;

    binary::Object object;
    object.index = object_index;
    object.format = binary::Format::MachO;
    object.architecture = map_arch(cputype);
    object.address_width = is64 ? binary::AddressWidth::Bits64 : binary::AddressWidth::Bits32;
    object.endianness = big ? binary::Endianness::Big : binary::Endianness::Little;
    switch (filetype) {
    case 1:
        object.kind = binary::ObjectKind::Relocatable;
        break;
    case 2:
        object.kind = binary::ObjectKind::Executable;
        break;
    case 6:
        object.kind = binary::ObjectKind::SharedLibrary;
        break;
    default:
        object.kind = binary::ObjectKind::Object;
        break;
    }

    // Bound the number of load commands to a sane ceiling for adversarial input.
    if (ncmds > 100000U) {
        return Result<binary::Object>::err(make_error(ErrorCode::MalformedInput, "Mach-O ncmds is implausible"));
    }

    struct SymtabInfo {
        std::uint32_t symoff{0};
        std::uint32_t nsyms{0};
        std::uint32_t stroff{0};
        std::uint32_t strsize{0};
        bool present{false};
    } symtab;

    std::size_t offset = header_size;
    for (std::uint32_t i = 0; i < ncmds; ++i) {
        if (offset + 8 > bytes.size()) {
            break;
        }
        const std::uint32_t cmd = reader.u32(offset);
        const std::uint32_t cmdsize = reader.u32(offset + 4);
        if (cmdsize < 8 || offset + cmdsize > bytes.size()) {
            break;
        }

        if (cmd == lc_segment_64 || cmd == lc_segment) {
            const bool seg64 = cmd == lc_segment_64;
            const std::string segname = reader.fixed_string(offset + 8, 16);
            const std::size_t base = offset + 24;
            std::uint64_t vmaddr = 0;
            std::uint64_t vmsize = 0;
            std::uint64_t fileoff = 0;
            std::uint32_t initprot = 0;
            std::uint32_t nsects = 0;
            std::size_t sect_base = 0;
            if (seg64) {
                vmaddr = reader.u64(base);
                vmsize = reader.u64(base + 8);
                fileoff = reader.u64(base + 16);
                initprot = reader.u32(base + 36);
                nsects = reader.u32(base + 40);
                sect_base = offset + 72;
            } else {
                vmaddr = reader.u32(base);
                vmsize = reader.u32(base + 4);
                fileoff = reader.u32(base + 8);
                initprot = reader.u32(base + 20);
                nsects = reader.u32(base + 24);
                sect_base = offset + 56;
            }

            binary::Segment segment;
            segment.name = segname;
            segment.address = vmaddr;
            segment.offset = fileoff;
            segment.size = vmsize;
            segment.readable = (initprot & vm_prot_read) != 0U;
            segment.writable = (initprot & vm_prot_write) != 0U;
            segment.executable = (initprot & vm_prot_execute) != 0U;
            segment.detail = "segment";
            object.segments.push_back(std::move(segment));

            const std::size_t sect_size = seg64 ? 80U : 68U;
            if (nsects > 100000U) {
                break;
            }
            for (std::uint32_t s = 0; s < nsects; ++s) {
                const std::size_t so = sect_base + (static_cast<std::size_t>(s) * sect_size);
                if (so + sect_size > bytes.size()) {
                    break;
                }
                binary::Section section;
                section.name = reader.fixed_string(so, 16);
                section.object_index = object_index;
                section.index = s;
                if (seg64) {
                    section.address = reader.u64(so + 32);
                    section.size = reader.u64(so + 40);
                    section.offset = reader.u32(so + 48);
                } else {
                    section.address = reader.u32(so + 32);
                    section.size = reader.u32(so + 36);
                    section.offset = reader.u32(so + 40);
                }
                section.readable = (initprot & vm_prot_read) != 0U;
                section.writable = (initprot & vm_prot_write) != 0U;
                section.executable = (initprot & vm_prot_execute) != 0U || section.name == "__text";
                if (section.executable) {
                    section.kind = binary::SectionKind::Code;
                } else if (section.name == "__cstring" || section.name.find("string") != std::string::npos) {
                    section.kind = binary::SectionKind::CString;
                    section.contains_strings = true;
                } else if (!section.writable) {
                    section.kind = binary::SectionKind::ReadOnlyData;
                } else {
                    section.kind = binary::SectionKind::Data;
                }
                object.sections.push_back(std::move(section));
            }
        } else if (cmd == lc_symtab) {
            symtab.symoff = reader.u32(offset + 8);
            symtab.nsyms = reader.u32(offset + 12);
            symtab.stroff = reader.u32(offset + 16);
            symtab.strsize = reader.u32(offset + 20);
            symtab.present = true;
        } else if (cmd == lc_load_dylib || cmd == lc_load_weak_dylib || cmd == lc_reexport_dylib) {
            const std::uint32_t name_off = reader.u32(offset + 8);
            if (name_off < cmdsize) {
                std::string lib = reader.c_string(offset + name_off);
                // Keep just the leaf name for readability (e.g. libSystem.B.dylib).
                const auto slash = lib.find_last_of('/');
                object.libraries.push_back(slash == std::string::npos ? lib : lib.substr(slash + 1));
            }
        } else if (cmd == lc_main) {
            object.entry = reader.u64(offset + 8);
        }

        offset += cmdsize;
    }

    // Parse the symbol table.
    if (symtab.present && symtab.nsyms <= 5000000U) {
        const std::size_t nlist_size = is64 ? 16U : 12U;
        for (std::uint32_t i = 0; i < symtab.nsyms; ++i) {
            const std::size_t no = symtab.symoff + (static_cast<std::size_t>(i) * nlist_size);
            if (no + nlist_size > bytes.size()) {
                break;
            }
            const std::uint32_t strx = reader.u32(no);
            const std::uint8_t type = reader.u8(no + 4);
            const std::uint16_t desc = reader.u16(no + 6);
            const std::uint64_t value = is64 ? reader.u64(no + 8) : reader.u32(no + 8);

            if ((type & n_stab) != 0U) {
                continue; // debug symbol
            }
            std::string name;
            if (strx != 0 && strx < symtab.strsize) {
                name = reader.c_string(symtab.stroff + strx);
            }
            if (name.empty()) {
                continue;
            }
            // Skip clang assembler temporaries (section-boundary labels like ltmp0).
            if (name.rfind("ltmp", 0) == 0 || name.rfind("l_", 0) == 0) {
                continue;
            }
            // Mach-O C symbols carry a leading underscore; strip it for display.
            std::string display = (name[0] == '_') ? name.substr(1) : name;

            binary::Symbol symbol;
            symbol.name = display;
            symbol.raw_name = name;
            symbol.object_index = object_index;
            symbol.address = value;
            symbol.section_index = reader.u8(no + 5);
            symbol.dynamic = true;
            symbol.type = binary::SymbolType::Function;

            const std::uint8_t ntype = type & n_type_mask;
            const bool ext = (type & n_ext) != 0U;
            if (ntype == n_undf) {
                symbol.bind = binary::SymbolBind::Imported;
                symbol.defined = false;
                const std::uint32_t ordinal = static_cast<std::uint32_t>((desc >> 8) & 0xffU);
                if (ordinal >= 1 && ordinal <= object.libraries.size()) {
                    symbol.library = object.libraries[ordinal - 1];
                }
            } else if (ntype == n_sect && ext) {
                symbol.bind = binary::SymbolBind::Exported;
                symbol.defined = true;
            } else {
                symbol.bind = ext ? binary::SymbolBind::Global : binary::SymbolBind::Local;
                symbol.defined = true;
            }
            object.symbols.push_back(std::move(symbol));
        }
    }

    extract_strings(bytes, object);
    return Result<binary::Object>::ok(std::move(object));
}

class MachoBinaryFile final : public binary::BinaryFile {
public:
    MachoBinaryFile(binary::FileView view, std::vector<std::uint8_t> image)
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

std::uint32_t read_be32(const std::vector<std::uint8_t>& bytes, std::size_t offset)
{
    if (offset + 4 > bytes.size()) {
        return 0;
    }
    return (static_cast<std::uint32_t>(bytes[offset]) << 24) | (static_cast<std::uint32_t>(bytes[offset + 1]) << 16) |
           (static_cast<std::uint32_t>(bytes[offset + 2]) << 8) | bytes[offset + 3];
}

} // namespace

Result<File> parse_bytes(std::string source_name, std::vector<std::uint8_t> bytes)
{
    if (bytes.size() < 4) {
        return Result<File>::err(make_error(ErrorCode::MalformedInput, "file too small for Mach-O"));
    }
    const std::uint32_t magic_be = read_be32(bytes, 0);

    std::vector<std::uint8_t> thin;
    if (magic_be == fat_magic || magic_be == fat_cigam || magic_be == fat_magic_64 || magic_be == fat_cigam_64) {
        // Fat/universal: pick a slice (prefer arm64, else the first).
        const bool fat64 = magic_be == fat_magic_64 || magic_be == fat_cigam_64;
        const std::uint32_t nfat = read_be32(bytes, 4);
        if (nfat == 0 || nfat > 64) {
            return Result<File>::err(make_error(ErrorCode::MalformedInput, "implausible fat arch count"));
        }
        const std::size_t arch_size = fat64 ? 32U : 20U;
        std::size_t chosen_off = 0;
        std::size_t chosen_size = 0;
        for (std::uint32_t i = 0; i < nfat; ++i) {
            const std::size_t base = 8 + (static_cast<std::size_t>(i) * arch_size);
            if (base + arch_size > bytes.size()) {
                break;
            }
            const std::uint32_t cputype = read_be32(bytes, base);
            std::size_t off = 0;
            std::size_t sz = 0;
            if (fat64) {
                // offset/size are 64-bit at base+8 / base+16
                for (int b = 0; b < 8; ++b) {
                    off = (off << 8) | bytes[base + 8 + static_cast<std::size_t>(b)];
                    sz = (sz << 8) | bytes[base + 16 + static_cast<std::size_t>(b)];
                }
            } else {
                off = read_be32(bytes, base + 8);
                sz = read_be32(bytes, base + 12);
            }
            const bool is_arm64 = (cputype & ~cpu_arch_abi64) == cpu_type_arm && (cputype & cpu_arch_abi64) != 0U;
            if (chosen_size == 0 || is_arm64) {
                chosen_off = off;
                chosen_size = sz;
                if (is_arm64) {
                    break;
                }
            }
        }
        if (chosen_size == 0 || chosen_off + chosen_size > bytes.size()) {
            return Result<File>::err(make_error(ErrorCode::MalformedInput, "fat slice out of bounds"));
        }
        thin.assign(bytes.begin() + static_cast<std::ptrdiff_t>(chosen_off),
            bytes.begin() + static_cast<std::ptrdiff_t>(chosen_off + chosen_size));
    } else {
        thin = std::move(bytes);
    }

    Result<binary::Object> object = parse_thin(thin, 0);
    if (!object) {
        return Result<File>::err(std::move(object).error());
    }

    File file;
    file.view.source_name = std::move(source_name);
    file.view.format = binary::Format::MachO;
    const std::size_t prefix = std::min<std::size_t>(16U, thin.size());
    file.view.first_bytes.assign(thin.begin(), thin.begin() + static_cast<std::ptrdiff_t>(prefix));
    file.view.objects.push_back(std::move(object).value());
    file.object_images.push_back(thin);
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

Result<std::unique_ptr<binary::BinaryFile>> open_bytes(std::string source_name, std::vector<std::uint8_t> bytes)
{
    Result<File> parsed = parse_bytes(std::move(source_name), std::move(bytes));
    if (!parsed) {
        return Result<std::unique_ptr<binary::BinaryFile>>::err(std::move(parsed).error());
    }
    File file = std::move(parsed).value();
    std::vector<std::uint8_t> image = file.object_images.empty() ? std::vector<std::uint8_t>{} : file.object_images.front();
    return Result<std::unique_ptr<binary::BinaryFile>>::ok(
        std::make_unique<MachoBinaryFile>(std::move(file.view), std::move(image)));
}

Result<std::unique_ptr<binary::BinaryFile>> open_file(const std::filesystem::path& path)
{
    Result<File> parsed = parse_file(path);
    if (!parsed) {
        return Result<std::unique_ptr<binary::BinaryFile>>::err(std::move(parsed).error());
    }
    File file = std::move(parsed).value();
    std::vector<std::uint8_t> image = file.object_images.empty() ? std::vector<std::uint8_t>{} : file.object_images.front();
    return Result<std::unique_ptr<binary::BinaryFile>>::ok(
        std::make_unique<MachoBinaryFile>(std::move(file.view), std::move(image)));
}

} // namespace roe::macho
