# roe v1 Public Interfaces

The public headers in `include/roe/` are the source of truth. APIs are C++17,
use `#pragma once`, return `roe::Result<T>` for expected failures, and do not
throw for control flow.

## Core: `include/roe/core.hpp`

Namespace: `roe`

Types:

- `enum class ErrorCode`
- `struct Error`
- `template <typename T> class Result`
- `template <> class Result<void>`

Contract:

- `Result<T>::ok(...)` constructs successful results.
- `Result<T>::err(Error)` constructs failed results.
- `has_value()`, `operator bool()`, `value()`, and `error()` expose state.
- Calling `value()` on an error or `error()` on success is a programmer error and may assert.

## Binary Model: `include/roe/binary.hpp`

Namespace: `roe::binary`

Required value types:

- `enum class Format`
- `enum class Architecture`
- `enum class AddressWidth`
- `enum class Endianness`
- `enum class ObjectKind`
- `enum class SectionKind`
- `enum class SymbolBind`
- `enum class SymbolType`
- `enum class RelocationEncoding`
- `struct Section`
- `struct Symbol`
- `struct Relocation`
- `struct StringLiteral`
- `struct Object`
- `struct SectionBytes`
- `struct FileView`
- `class BinaryFile`

Required entry points:

- `Format detect_format(const std::vector<std::uint8_t>& bytes) noexcept;`
- `Result<std::unique_ptr<BinaryFile>> load_file(const std::filesystem::path& path);`
- `Result<std::unique_ptr<BinaryFile>> load_bytes(std::string source_name, std::vector<std::uint8_t> bytes);`
- `std::optional<Object> primary_object(const FileView& file);`
- `std::optional<Section> find_section(const FileView& file, std::size_t object_index, std::string_view name);`
- `std::vector<Symbol> function_symbols(const FileView& file, std::size_t object_index);`
- `std::optional<Symbol> find_symbol(const FileView& file, std::size_t object_index, std::string_view name);`
- `std::string_view format_name(Format format) noexcept;`
- `std::string_view architecture_name(Architecture architecture) noexcept;`
- `std::string first_bytes_hex(const std::vector<std::uint8_t>& bytes, std::size_t limit = 16);`

`BinaryFile::view()` returns normalized metadata for all architecture slices and
archive members. `BinaryFile::section_bytes()` returns owned bytes because the
selected section may come from an archive member or fat-binary slice.

## ELF Parser: `include/roe/elf.hpp`

Namespace: `roe::elf`

Existing v0.1 entry points remain:

- `Result<File> parse_file(const std::filesystem::path& path);`
- `Result<File> parse_bytes(std::string source_name, std::vector<std::uint8_t> bytes);`
- `std::optional<Section> find_section(const File& file, std::string_view name);`
- `std::vector<Symbol> function_symbols(const File& file);`
- `std::optional<Symbol> find_symbol(const File& file, std::string_view name);`
- `std::optional<SectionBytes> section_bytes(const File& file, const Section& section);`

v1 adapter entry points:

- `Result<std::unique_ptr<binary::BinaryFile>> open_file(const std::filesystem::path& path);`
- `Result<std::unique_ptr<binary::BinaryFile>> open_bytes(std::string source_name, std::vector<std::uint8_t> bytes);`

Parser failures must use `ErrorCode::FileIo`, `ErrorCode::MalformedInput`,
`ErrorCode::UnsupportedFormat`, or `ErrorCode::NotFound`.

## Mach-O Parser: `include/roe/macho.hpp`

Namespace: `roe::macho`

Required value types:

- `struct File`

Required entry points:

- `Result<File> parse_file(const std::filesystem::path& path);`
- `Result<File> parse_bytes(std::string source_name, std::vector<std::uint8_t> bytes);`
- `Result<std::unique_ptr<binary::BinaryFile>> open_file(const std::filesystem::path& path);`
- `Result<std::unique_ptr<binary::BinaryFile>> open_bytes(std::string source_name, std::vector<std::uint8_t> bytes);`

Must support x86-64, ARM64, and fat/universal containers. Unsupported valid
Mach-O CPU types return `ErrorCode::UnsupportedFormat`.

## PE/COFF Parser: `include/roe/pe.hpp`

Namespace: `roe::pe`

Required value types:

- `struct File`

Required entry points:

- `Result<File> parse_file(const std::filesystem::path& path);`
- `Result<File> parse_bytes(std::string source_name, std::vector<std::uint8_t> bytes);`
- `Result<std::unique_ptr<binary::BinaryFile>> open_file(const std::filesystem::path& path);`
- `Result<std::unique_ptr<binary::BinaryFile>> open_bytes(std::string source_name, std::vector<std::uint8_t> bytes);`

Must support `.exe`, `.dll`, COFF objects, x86, x86-64, ARM32, and ARM64.
PDB lookup paths are exposed through `pe::File::pdb_path` for `roe::debug`.

## Archive Parser: `include/roe/archive.hpp`

Namespace: `roe::archive`

Required value types:

- `struct Member`
- `struct File`

Required entry points:

- `Result<File> parse_file(const std::filesystem::path& path);`
- `Result<File> parse_bytes(std::string source_name, std::vector<std::uint8_t> bytes);`
- `Result<std::unique_ptr<binary::BinaryFile>> open_file(const std::filesystem::path& path);`
- `Result<std::unique_ptr<binary::BinaryFile>> open_bytes(std::string source_name, std::vector<std::uint8_t> bytes);`

Archive parsers expose each object member through `binary::FileView::objects`.
Malformed member headers return `ErrorCode::MalformedInput`.

## Disassembly: `include/roe/disasm.hpp`

Namespace: `roe::disasm`

Required value types:

- `enum class Architecture`
- `enum class Syntax`
- `enum class BranchKind`
- `struct CodeBuffer`
- `struct Options`
- `struct Instruction`

v1 entry points:

- `Result<std::vector<Instruction>> disassemble_bytes(CodeBuffer code, const Options& options);`
- `Result<Options> options_for(binary::Architecture architecture, Syntax syntax = Syntax::Intel);`
- `Result<std::vector<Instruction>> disassemble_section(const binary::SectionBytes& section, const Options& options);`
- `Result<std::vector<Instruction>> disassemble_function(const binary::BinaryFile& file, const binary::Object& object, const binary::Symbol& symbol, const Options& options);`
- `bool is_branch(BranchKind kind) noexcept;`
- `bool is_terminal(BranchKind kind) noexcept;`

Legacy ELF entry points remain during migration:

- `Result<std::vector<Instruction>> disassemble_function(const elf::File& file, const elf::Symbol& symbol, const Options& options);`
- `Result<std::vector<Instruction>> disassemble_section(const elf::File& file, const elf::Section& section, const Options& options);`

Required architecture coverage:

- x86
- x86-64
- ARM32 ARM mode
- ARM32 Thumb mode
- AArch64
- RISC-V 32
- RISC-V 64
- MIPS 32 little and big endian
- MIPS 64 little and big endian
- PowerPC 32
- PowerPC 64 little and big endian

## Resolver: `include/roe/resolver.hpp`

Namespace: `roe::resolver`

Required entry points:

- `Result<Index> build_index(const binary::BinaryFile& file, const Options& options = {});`
- `Result<Index> build_index(const elf::File& file, const Options& options = {});`
- `std::optional<ResolvedSymbol> symbol_at(const Index& index, std::uint64_t address);`
- `std::optional<ResolvedSymbol> nearest_symbol(const Index& index, std::uint64_t address);`
- `std::optional<ResolvedReference> relocation_at(const Index& index, std::uint64_t address);`
- `std::vector<AnnotatedInstruction> annotate(const Index& index, const std::vector<disasm::Instruction>& instructions);`
- `std::string demangle(std::string_view name);`

`build_index(binary::BinaryFile)` must populate:

- exact and nearest symbols
- synthetic import/PLT symbols such as `printf@plt`
- relocations and references
- string literals from read-only string sections
- demangled names for C++, MSVC, Rust legacy, and Rust v0 symbols where supported

## Debug/Source: `include/roe/debug.hpp`

Namespace: `roe::debug`

Required entry points:

- `Result<SourceMap> load_source_map(const binary::BinaryFile& file, std::size_t object_index);`
- `std::optional<SourceLocation> source_at(const SourceMap& map, std::uint64_t address);`
- `std::vector<SourceInstruction> interleave(const SourceMap& map, const std::vector<disasm::Instruction>& instructions);`

If no debug information exists, `load_source_map` returns a successful
`SourceMap` with `Format::None` and a single fallback message. Malformed debug
sections inside an otherwise usable binary must not make non-source workflows
fail.

## Features: `include/roe/features.hpp`

Namespace: `roe::features`

Required entry points:

- `Result<std::vector<binary::Symbol>> filter_functions(const std::vector<binary::Symbol>& functions, std::string_view regex_pattern);`
- `std::vector<binary::Symbol> functions_calling(const std::vector<FunctionBody>& functions, std::string_view symbol_name);`
- `std::vector<binary::Symbol> functions_containing_string(const std::vector<FunctionBody>& functions, std::string_view text);`
- `std::vector<Xref> find_xrefs(const std::vector<FunctionBody>& functions, std::string_view target_name);`
- `std::vector<FunctionStats> compute_stats(const std::vector<FunctionBody>& functions);`
- `std::vector<resolver::AnnotatedInstruction> annotate_string_references(const binary::Object& object, const std::vector<resolver::AnnotatedInstruction>& instructions);`

Regex errors return `ErrorCode::Usage`. String annotations truncate rendered
strings to 64 characters in the formatter, not in the data model.

## Watcher: `include/roe/watcher.hpp`

Namespace: `roe::watcher`

Required entry point:

- `Result<void> watch_file(const std::filesystem::path& path, const Options& options, Callback callback);`

Linux uses inotify, macOS/BSD uses kqueue, and Windows uses
ReadDirectoryChangesW. Unsupported platforms return
`ErrorCode::UnsupportedFormat` with a clear message.

## Formatting: `include/roe/format.hpp`

Namespace: `roe::format`

Required entry points:

- `Options default_options();`
- `bool color_enabled(const Options& options) noexcept;`
- `Result<std::string> render_banner();`
- `Result<std::string> render_version();`
- `Result<std::string> render_help();`
- `Result<std::string> render_help_topic(const std::string& topic);`
- `Result<std::string> render_error(const Error& error, const Options& options);`
- `Result<std::string> render_function_list(const binary::FileView& file, const resolver::Index& index, const Options& options);`
- `Result<std::string> render_function_list(const elf::File& file, const resolver::Index& index, const Options& options);`
- `Result<std::string> render_disassembly(const std::vector<resolver::AnnotatedInstruction>& instructions, const Options& options);`
- `Result<std::string> render_json(const std::vector<resolver::AnnotatedInstruction>& instructions, const Options& options);`
- `Result<std::string> render_xrefs(const std::vector<features::Xref>& xrefs, const Options& options);`
- `Result<std::string> render_stats(const std::vector<features::FunctionStats>& stats, const Options& options);`
- `Result<std::string> render_sections(const binary::FileView& file, const Options& options);`
- `Result<std::string> render_completions(const std::string& shell);`

Address text must be preserved. Raw instruction bytes are hidden unless
`Options::show_bytes` is true.

## CLI: `include/roe/cli.hpp`

Namespace: `roe::cli`

Required entry points:

- `Result<Arguments> parse_args(int argc, char** argv);`
- `int run(const Arguments& args, std::ostream& out, std::ostream& err);`
- `int main_entry(int argc, char** argv, std::ostream& out, std::ostream& err);`

Exit codes:

- `0`: ok
- `1`: usage error
- `2`: file/input error
- `3`: disassembly or resolver error

Every new flag must be represented in `Arguments`, `--help`, topic help,
`docs/roe.1`, and tests.

## Version: `include/roe/version.hpp`

Namespace: `roe`

Constants:

- `version_major`
- `version_minor`
- `version_patch`
- `version_string`
- `program_name`
- `build_commit`
- `build_date`
- `capstone_version`

Build metadata is supplied by CMake compile definitions and falls back to
`"unknown"` when building outside CMake.
