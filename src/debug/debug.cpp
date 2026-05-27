// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The roe Authors

#include "roe/debug.hpp"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace roe::debug {
namespace {

// DWARF line-number standard / extended opcodes and v5 form constants used below.
constexpr std::uint8_t dw_lns_copy = 1;
constexpr std::uint8_t dw_lns_advance_pc = 2;
constexpr std::uint8_t dw_lns_advance_line = 3;
constexpr std::uint8_t dw_lns_set_file = 4;
constexpr std::uint8_t dw_lns_set_column = 5;
constexpr std::uint8_t dw_lns_negate_stmt = 6;
constexpr std::uint8_t dw_lns_set_basic_block = 7;
constexpr std::uint8_t dw_lns_const_add_pc = 8;
constexpr std::uint8_t dw_lns_fixed_advance_pc = 9;
constexpr std::uint8_t dw_lns_set_prologue_end = 10;
constexpr std::uint8_t dw_lns_set_epilogue_begin = 11;
constexpr std::uint8_t dw_lns_set_isa = 12;

constexpr std::uint8_t dw_lne_end_sequence = 1;
constexpr std::uint8_t dw_lne_set_address = 2;
constexpr std::uint8_t dw_lne_set_discriminator = 4;

constexpr std::uint64_t dw_lnct_path = 1;
constexpr std::uint64_t dw_lnct_directory_index = 2;

constexpr std::uint64_t dw_form_data1 = 0x0b;
constexpr std::uint64_t dw_form_data2 = 0x05;
constexpr std::uint64_t dw_form_data4 = 0x06;
constexpr std::uint64_t dw_form_data8 = 0x07;
constexpr std::uint64_t dw_form_data16 = 0x1e;
constexpr std::uint64_t dw_form_string = 0x08;
constexpr std::uint64_t dw_form_strp = 0x0e;
constexpr std::uint64_t dw_form_line_strp = 0x1f;
constexpr std::uint64_t dw_form_udata = 0x0f;
constexpr std::uint64_t dw_form_strx = 0x1a;
constexpr std::uint64_t dw_form_strx1 = 0x25;
constexpr std::uint64_t dw_form_strx2 = 0x26;
constexpr std::uint64_t dw_form_strx3 = 0x27;
constexpr std::uint64_t dw_form_strx4 = 0x28;

// Bounds-checked little/big-endian cursor over a DWARF section.
class Cursor {
public:
    Cursor(const std::vector<std::uint8_t>& bytes, bool big_endian) noexcept
        : bytes_(bytes), big_endian_(big_endian)
    {
    }

    [[nodiscard]] bool ok() const noexcept { return !error_; }
    [[nodiscard]] std::size_t position() const noexcept { return pos_; }
    [[nodiscard]] bool at_end() const noexcept { return pos_ >= bytes_.size(); }
    void seek(std::size_t position) noexcept { pos_ = position; }

    std::uint8_t u8() noexcept
    {
        if (pos_ + 1 > bytes_.size()) {
            error_ = true;
            return 0;
        }
        return bytes_[pos_++];
    }

    std::uint16_t u16() noexcept
    {
        const std::uint8_t a = u8();
        const std::uint8_t b = u8();
        return big_endian_ ? static_cast<std::uint16_t>((a << 8) | b)
                           : static_cast<std::uint16_t>((b << 8) | a);
    }

    std::uint32_t u32() noexcept
    {
        std::uint32_t value = 0;
        if (big_endian_) {
            for (int i = 0; i < 4; ++i) {
                value = (value << 8) | u8();
            }
        } else {
            for (int i = 0; i < 4; ++i) {
                value |= static_cast<std::uint32_t>(u8()) << (8 * i);
            }
        }
        return value;
    }

    std::uint64_t u64() noexcept
    {
        std::uint64_t value = 0;
        if (big_endian_) {
            for (int i = 0; i < 8; ++i) {
                value = (value << 8) | u8();
            }
        } else {
            for (int i = 0; i < 8; ++i) {
                value |= static_cast<std::uint64_t>(u8()) << (8 * i);
            }
        }
        return value;
    }

    std::uint64_t uleb() noexcept
    {
        std::uint64_t result = 0;
        unsigned shift = 0;
        while (true) {
            const std::uint8_t byte = u8();
            if (shift < 64) {
                result |= static_cast<std::uint64_t>(byte & 0x7fU) << shift;
            }
            shift += 7;
            if ((byte & 0x80U) == 0) {
                break;
            }
            if (error_ || shift > 70) {
                break;
            }
        }
        return result;
    }

    std::int64_t sleb() noexcept
    {
        std::int64_t result = 0;
        unsigned shift = 0;
        std::uint8_t byte = 0;
        do {
            byte = u8();
            if (shift < 64) {
                result |= static_cast<std::int64_t>(byte & 0x7fU) << shift;
            }
            shift += 7;
            if (error_ || shift > 70) {
                break;
            }
        } while ((byte & 0x80U) != 0);
        if (shift < 64 && (byte & 0x40U) != 0) {
            result |= -(static_cast<std::int64_t>(1) << shift);
        }
        return result;
    }

    std::string cstring()
    {
        std::string out;
        while (pos_ < bytes_.size()) {
            const char character = static_cast<char>(bytes_[pos_++]);
            if (character == '\0') {
                return out;
            }
            out.push_back(character);
        }
        error_ = true;
        return out;
    }

    void skip(std::size_t count) noexcept
    {
        if (pos_ + count > bytes_.size()) {
            pos_ = bytes_.size();
            error_ = true;
        } else {
            pos_ += count;
        }
    }

private:
    const std::vector<std::uint8_t>& bytes_;
    std::size_t pos_{0};
    bool big_endian_{false};
    bool error_{false};
};

std::string string_at(const std::vector<std::uint8_t>& table, std::uint64_t offset)
{
    if (offset >= table.size()) {
        return {};
    }
    std::string out;
    for (std::size_t i = static_cast<std::size_t>(offset); i < table.size() && table[i] != 0; ++i) {
        out.push_back(static_cast<char>(table[i]));
    }
    return out;
}

struct Tables {
    std::vector<std::uint8_t> line;
    std::vector<std::uint8_t> line_str;
    std::vector<std::uint8_t> str;
    bool big_endian{false};
};

std::optional<std::vector<std::uint8_t>> section_bytes_named(
    const binary::BinaryFile& file,
    const binary::Object& object,
    std::string_view name)
{
    for (const binary::Section& section : object.sections) {
        if (section.name == name) {
            Result<binary::SectionBytes> bytes = file.section_bytes(section);
            if (bytes) {
                return std::move(bytes).value().bytes;
            }
        }
    }
    return std::nullopt;
}

struct Row {
    std::uint64_t address{0};
    std::uint64_t file{0};
    std::uint32_t line{0};
    std::uint32_t column{0};
};

// Read one v5 directory/file entry's path string, given the entry formats.
std::string read_v5_path(Cursor& cursor, const std::vector<std::pair<std::uint64_t, std::uint64_t>>& formats,
    const Tables& tables, bool dwarf64)
{
    std::string path;
    for (const auto& [content_type, form] : formats) {
        if (form == dw_form_string) {
            const std::string value = cursor.cstring();
            if (content_type == dw_lnct_path) {
                path = value;
            }
        } else if (form == dw_form_line_strp || form == dw_form_strp) {
            const std::uint64_t offset = dwarf64 ? cursor.u64() : cursor.u32();
            if (content_type == dw_lnct_path) {
                path = string_at(form == dw_form_line_strp ? tables.line_str : tables.str, offset);
            }
        } else if (form == dw_form_udata || form == dw_form_strx) {
            cursor.uleb();
        } else if (form == dw_form_strx1 || form == dw_form_data1) {
            cursor.skip(1);
        } else if (form == dw_form_strx2 || form == dw_form_data2) {
            cursor.skip(2);
        } else if (form == dw_form_strx3) {
            cursor.skip(3);
        } else if (form == dw_form_strx4 || form == dw_form_data4) {
            cursor.skip(4);
        } else if (form == dw_form_data8) {
            cursor.skip(8);
        } else if (form == dw_form_data16) {
            cursor.skip(16);
        } else {
            cursor.uleb(); // best effort for unmodeled forms
        }
    }
    return path;
}

// Parse one line-number program unit starting at the cursor; append rows and a
// per-unit file-index -> resolved-path table. Returns the offset just past the unit.
void parse_unit(Cursor& cursor, const Tables& tables, const std::string& comp_dir_hint,
    std::vector<Row>& rows, std::vector<std::string>& file_paths)
{
    const std::size_t unit_start = cursor.position();
    bool dwarf64 = false;
    std::uint64_t unit_length = cursor.u32();
    if (unit_length == 0xffffffffU) {
        dwarf64 = true;
        unit_length = cursor.u64();
    }
    const std::size_t unit_end = cursor.position() + static_cast<std::size_t>(unit_length);

    const std::uint16_t version = cursor.u16();
    if (version < 2 || version > 5) {
        cursor.seek(unit_end);
        return;
    }
    if (version >= 5) {
        cursor.u8(); // address_size
        cursor.u8(); // segment_selector_size
    }
    const std::uint64_t header_length = dwarf64 ? cursor.u64() : cursor.u32();
    const std::size_t program_start = cursor.position() + static_cast<std::size_t>(header_length);

    const std::uint8_t minimum_instruction_length = cursor.u8();
    if (version >= 4) {
        cursor.u8(); // maximum_operations_per_instruction
    }
    cursor.u8(); // default_is_stmt
    const std::int8_t line_base = static_cast<std::int8_t>(cursor.u8());
    const std::uint8_t line_range = cursor.u8();
    const std::uint8_t opcode_base = cursor.u8();
    std::vector<std::uint8_t> standard_opcode_lengths(opcode_base > 0 ? opcode_base - 1U : 0U);
    for (std::uint8_t i = 0; i + 1 < opcode_base; ++i) {
        standard_opcode_lengths[i] = cursor.u8();
    }

    std::vector<std::string> directories;
    std::vector<std::string> files; // resolved paths, indexed as the program references them

    if (version <= 4) {
        directories.emplace_back(comp_dir_hint); // index 0 = compilation directory
        while (true) {
            const std::string dir = cursor.cstring();
            if (dir.empty()) {
                break;
            }
            directories.push_back(dir);
        }
        files.emplace_back(); // index 0 unused in v<=4
        while (true) {
            const std::string name = cursor.cstring();
            if (name.empty()) {
                break;
            }
            const std::uint64_t dir_index = cursor.uleb();
            cursor.uleb(); // mtime
            cursor.uleb(); // size
            std::string path = name;
            if (!name.empty() && name[0] != '/' && dir_index < directories.size()) {
                const std::string& dir = directories[static_cast<std::size_t>(dir_index)];
                path = dir.empty() ? name : dir + "/" + name;
            }
            files.push_back(path);
        }
    } else {
        // DWARF 5 directory table
        const std::uint8_t dir_format_count = cursor.u8();
        std::vector<std::pair<std::uint64_t, std::uint64_t>> dir_formats;
        for (std::uint8_t i = 0; i < dir_format_count; ++i) {
            const std::uint64_t content = cursor.uleb();
            const std::uint64_t form = cursor.uleb();
            dir_formats.emplace_back(content, form);
        }
        const std::uint64_t dir_count = cursor.uleb();
        for (std::uint64_t i = 0; i < dir_count && cursor.ok(); ++i) {
            directories.push_back(read_v5_path(cursor, dir_formats, tables, dwarf64));
        }
        // DWARF 5 file table
        const std::uint8_t file_format_count = cursor.u8();
        std::vector<std::pair<std::uint64_t, std::uint64_t>> file_formats;
        for (std::uint8_t i = 0; i < file_format_count; ++i) {
            const std::uint64_t content = cursor.uleb();
            const std::uint64_t form = cursor.uleb();
            file_formats.emplace_back(content, form);
        }
        const std::uint64_t file_count = cursor.uleb();
        for (std::uint64_t i = 0; i < file_count && cursor.ok(); ++i) {
            // We need both the path and the directory index; re-read with awareness.
            std::string name;
            std::uint64_t dir_index = 0;
            for (const auto& [content_type, form] : file_formats) {
                if (form == dw_form_string) {
                    const std::string value = cursor.cstring();
                    if (content_type == dw_lnct_path) {
                        name = value;
                    }
                } else if (form == dw_form_line_strp || form == dw_form_strp) {
                    const std::uint64_t offset = dwarf64 ? cursor.u64() : cursor.u32();
                    if (content_type == dw_lnct_path) {
                        name = string_at(form == dw_form_line_strp ? tables.line_str : tables.str, offset);
                    }
                } else if (form == dw_form_udata) {
                    const std::uint64_t value = cursor.uleb();
                    if (content_type == dw_lnct_directory_index) {
                        dir_index = value;
                    }
                } else if (form == dw_form_data1) {
                    const std::uint8_t value = cursor.u8();
                    if (content_type == dw_lnct_directory_index) {
                        dir_index = value;
                    }
                } else if (form == dw_form_data2) {
                    const std::uint16_t value = cursor.u16();
                    if (content_type == dw_lnct_directory_index) {
                        dir_index = value;
                    }
                } else if (form == dw_form_data4) {
                    cursor.skip(4);
                } else if (form == dw_form_data8) {
                    cursor.skip(8);
                } else if (form == dw_form_data16) {
                    cursor.skip(16);
                } else if (form == dw_form_strx1) {
                    cursor.skip(1);
                } else if (form == dw_form_strx2) {
                    cursor.skip(2);
                } else {
                    cursor.uleb();
                }
            }
            std::string path = name;
            if (!name.empty() && name[0] != '/' && dir_index < directories.size()) {
                const std::string& dir = directories[static_cast<std::size_t>(dir_index)];
                path = dir.empty() ? name : dir + "/" + name;
            }
            files.push_back(path);
        }
    }

    file_paths = files;

    // Run the line-number program.
    cursor.seek(program_start);
    std::uint64_t address = 0;
    std::uint64_t file = version >= 5 ? 0 : 1;
    std::int64_t line = 1;
    std::uint64_t column = 0;

    const auto emit = [&]() {
        Row row;
        row.address = address;
        row.file = file;
        row.line = line > 0 ? static_cast<std::uint32_t>(line) : 0U;
        row.column = static_cast<std::uint32_t>(column);
        rows.push_back(row);
    };
    const auto reset = [&]() {
        address = 0;
        file = version >= 5 ? 0 : 1;
        line = 1;
        column = 0;
    };

    while (cursor.position() < unit_end && cursor.ok()) {
        const std::uint8_t opcode = cursor.u8();
        if (opcode == 0) {
            // extended opcode
            const std::uint64_t length = cursor.uleb();
            const std::size_t next = cursor.position() + static_cast<std::size_t>(length);
            const std::uint8_t sub = cursor.u8();
            if (sub == dw_lne_end_sequence) {
                emit();
                reset();
            } else if (sub == dw_lne_set_address) {
                const std::size_t addr_size = (length >= 9) ? 8U : 4U;
                address = addr_size == 8U ? cursor.u64() : cursor.u32();
            } else if (sub == dw_lne_set_discriminator) {
                cursor.uleb();
            }
            cursor.seek(next);
        } else if (opcode < opcode_base) {
            switch (opcode) {
            case dw_lns_copy:
                emit();
                break;
            case dw_lns_advance_pc:
                address += cursor.uleb() * minimum_instruction_length;
                break;
            case dw_lns_advance_line:
                line += cursor.sleb();
                break;
            case dw_lns_set_file:
                file = cursor.uleb();
                break;
            case dw_lns_set_column:
                column = cursor.uleb();
                break;
            case dw_lns_negate_stmt:
            case dw_lns_set_basic_block:
            case dw_lns_set_prologue_end:
            case dw_lns_set_epilogue_begin:
                break;
            case dw_lns_const_add_pc:
                if (line_range != 0) {
                    address += static_cast<std::uint64_t>((255 - opcode_base) / line_range) * minimum_instruction_length;
                }
                break;
            case dw_lns_fixed_advance_pc:
                address += cursor.u16();
                break;
            case dw_lns_set_isa:
                cursor.uleb();
                break;
            default: {
                const std::uint8_t args = opcode - 1U < standard_opcode_lengths.size()
                    ? standard_opcode_lengths[opcode - 1U]
                    : 0U;
                for (std::uint8_t i = 0; i < args; ++i) {
                    cursor.uleb();
                }
                break;
            }
            }
        } else {
            // special opcode
            const std::uint8_t adjusted = static_cast<std::uint8_t>(opcode - opcode_base);
            if (line_range != 0) {
                address += static_cast<std::uint64_t>(adjusted / line_range) * minimum_instruction_length;
                line += line_base + static_cast<std::int64_t>(adjusted % line_range);
            }
            emit();
        }
    }

    cursor.seek(unit_end);
    static_cast<void>(unit_start);
}

std::vector<std::string>& source_lines(const std::string& path, std::map<std::string, std::vector<std::string>>& cache)
{
    const auto found = cache.find(path);
    if (found != cache.end()) {
        return found->second;
    }
    std::vector<std::string> lines;
    std::ifstream stream(path);
    if (stream) {
        std::string line;
        while (std::getline(stream, line)) {
            lines.push_back(line);
        }
    }
    return cache.emplace(path, std::move(lines)).first->second;
}

} // namespace

Result<SourceMap> load_source_map(const binary::BinaryFile& file, std::size_t object_index)
{
    SourceMap map;
    map.object_index = object_index;
    const binary::FileView& view = file.view();
    if (object_index >= view.objects.size()) {
        map.fallback_message = "no such object";
        return Result<SourceMap>::ok(std::move(map));
    }
    const binary::Object& object = view.objects[object_index];

    const std::optional<std::vector<std::uint8_t>> line = section_bytes_named(file, object, ".debug_line");
    if (!line.has_value() || line->empty()) {
        map.fallback_message = "no DWARF line information (.debug_line); rebuild with -g for --source";
        return Result<SourceMap>::ok(std::move(map));
    }

    Tables tables;
    tables.line = *line;
    tables.big_endian = object.endianness == binary::Endianness::Big;
    if (const auto line_str = section_bytes_named(file, object, ".debug_line_str")) {
        tables.line_str = *line_str;
    }
    if (const auto str = section_bytes_named(file, object, ".debug_str")) {
        tables.str = *str;
    }

    // Best-effort compilation-directory hint for DWARF<=4 relative paths.
    std::string comp_dir_hint = std::filesystem::path(view.source_name).parent_path().string();

    std::vector<Row> rows;
    Cursor cursor(tables.line, tables.big_endian);
    std::map<std::uint64_t, std::vector<std::string>> unit_files;
    std::uint64_t unit_id = 0;
    while (cursor.position() < tables.line.size() && cursor.ok()) {
        std::vector<std::string> file_paths;
        const std::size_t before = cursor.position();
        std::vector<Row> unit_rows;
        parse_unit(cursor, tables, comp_dir_hint, unit_rows, file_paths);
        if (cursor.position() <= before) {
            break; // no progress; avoid infinite loop on malformed input
        }
        for (Row& row : unit_rows) {
            row.file |= (unit_id << 32U); // tag rows with their unit for file lookup
            rows.push_back(row);
        }
        unit_files[unit_id] = std::move(file_paths);
        ++unit_id;
    }

    std::map<std::string, std::vector<std::string>> source_cache;
    map.format = Format::Dwarf;
    map.locations.reserve(rows.size());
    for (const Row& row : rows) {
        const std::uint64_t this_unit = row.file >> 32U;
        const std::uint64_t file_index = row.file & 0xffffffffULL;
        SourceLocation location;
        location.line = row.line;
        location.column = row.column;
        const auto unit = unit_files.find(this_unit);
        if (unit != unit_files.end() && file_index < unit->second.size()) {
            location.path = unit->second[static_cast<std::size_t>(file_index)];
        }
        if (!location.path.empty() && row.line > 0) {
            const std::vector<std::string>& lines = source_lines(location.path, source_cache);
            if (row.line <= lines.size()) {
                location.text = lines[row.line - 1];
            }
        }
        map.locations.emplace_back(row.address, std::move(location));
    }

    std::sort(map.locations.begin(), map.locations.end(),
        [](const auto& lhs, const auto& rhs) { return lhs.first < rhs.first; });

    if (map.locations.empty()) {
        map.fallback_message = "DWARF line table contained no usable rows";
    }
    return Result<SourceMap>::ok(std::move(map));
}

std::optional<SourceLocation> source_at(const SourceMap& map, std::uint64_t address)
{
    if (map.locations.empty()) {
        return std::nullopt;
    }
    const auto upper = std::upper_bound(map.locations.begin(), map.locations.end(), address,
        [](std::uint64_t value, const auto& entry) { return value < entry.first; });
    if (upper == map.locations.begin()) {
        return std::nullopt;
    }
    const auto& entry = *(upper - 1);
    if (entry.second.line == 0) {
        return std::nullopt;
    }
    return entry.second;
}

std::vector<SourceInstruction> interleave(
    const SourceMap& map,
    const std::vector<disasm::Instruction>& instructions)
{
    std::vector<SourceInstruction> out;
    out.reserve(instructions.size());
    for (const disasm::Instruction& instruction : instructions) {
        SourceInstruction entry;
        entry.instruction = instruction;
        entry.source = source_at(map, instruction.address);
        out.push_back(std::move(entry));
    }
    return out;
}

} // namespace roe::debug
