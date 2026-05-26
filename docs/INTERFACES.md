# roe Public Interfaces

The public headers in `include/roe/` are the source of truth. This document summarizes the exact contracts implementation agents must target. Public APIs are C++17, use `#pragma once`, return `roe::Result<T>` for expected failures, and do not throw for control flow.

## Core: `include/roe/core.hpp`

- Namespace: `roe`
- Types:
  - `enum class ErrorCode`
  - `struct Error`
  - `template <typename T> class Result`
  - `template <> class Result<void>`
- Contract:
  - `Result<T>::ok(...)` constructs successful results.
  - `Result<T>::err(Error)` constructs failed results.
  - `has_value()`, `operator bool()`, `value()`, and `error()` expose state.
  - Calling `value()` on an error or `error()` on success is a programmer error and may assert.

## ELF Parser: `include/roe/elf.hpp`

- Namespace: `roe::elf`
- Owns parsing from paths and bytes.
- Required entry points:
  - `Result<File> parse_file(const std::filesystem::path& path);`
  - `Result<File> parse_bytes(std::string source_name, std::vector<std::uint8_t> bytes);`
  - `std::optional<Section> find_section(const File& file, std::string_view name);`
  - `std::vector<Symbol> function_symbols(const File& file);`
  - `std::optional<Symbol> find_symbol(const File& file, std::string_view name);`
  - `std::optional<SectionBytes> section_bytes(const File& file, const Section& section);`
- Parser failures must use `ErrorCode::FileIo`, `ErrorCode::MalformedInput`, `ErrorCode::UnsupportedFormat`, or `ErrorCode::NotFound`.
- `File::image` owns file bytes so section byte views remain valid while the `File` is alive.

## Disassembly: `include/roe/disasm.hpp`

- Namespace: `roe::disasm`
- Owns instruction decoding and branch classification.
- Required entry points:
  - `Result<std::vector<Instruction>> disassemble_bytes(CodeBuffer code, const Options& options);`
  - `Result<std::vector<Instruction>> disassemble_function(const elf::File& file, const elf::Symbol& symbol, const Options& options);`
  - `Result<std::vector<Instruction>> disassemble_section(const elf::File& file, const elf::Section& section, const Options& options);`
  - `bool is_branch(BranchKind kind) noexcept;`
  - `bool is_terminal(BranchKind kind) noexcept;`
- x86-64 is required for v0.1.0. arm64 is represented in the interface but may return `UnsupportedFormat` until implemented.

## Resolver: `include/roe/resolver.hpp`

- Namespace: `roe::resolver`
- Owns symbol and relocation lookup.
- Required entry points:
  - `Result<Index> build_index(const elf::File& file, const Options& options = {});`
  - `std::optional<ResolvedSymbol> symbol_at(const Index& index, std::uint64_t address);`
  - `std::optional<ResolvedSymbol> nearest_symbol(const Index& index, std::uint64_t address);`
  - `std::optional<ResolvedReference> relocation_at(const Index& index, std::uint64_t address);`
  - `std::vector<AnnotatedInstruction> annotate(const Index& index, const std::vector<disasm::Instruction>& instructions);`
  - `std::string demangle(std::string_view name);`
- `AnnotatedInstruction::branch_target_symbol` is populated when a direct branch or call target starts at a known symbol, including synthesized PLT symbols.

## Formatting: `include/roe/format.hpp`

- Namespace: `roe::format`
- Owns all user-visible rendering.
- Required entry points:
  - `Options default_options();`
  - `bool color_enabled(const Options& options) noexcept;`
  - `Result<std::string> render_banner();`
  - `Result<std::string> render_help();`
  - `Result<std::string> render_error(const Error& error, const Options& options);`
  - `Result<std::string> render_function_list(const elf::File& file, const resolver::Index& index, const Options& options);`
  - `Result<std::string> render_disassembly(const std::vector<resolver::AnnotatedInstruction>& instructions, const Options& options);`
  - `Result<std::string> render_json(const std::vector<resolver::AnnotatedInstruction>& instructions, const Options& options);`
- Address text must be preserved. Formatters must not strip or normalize addresses away.
- Branch previews are presentation logic and are generated here.
- `Options::show_bytes` controls raw instruction byte rendering. Text output defaults to hiding bytes.

## CLI: `include/roe/cli.hpp`

- Namespace: `roe::cli`
- Owns argument parsing and workflow exit codes.
- Required entry points:
  - `Result<Arguments> parse_args(int argc, char** argv);`
  - `int run(const Arguments& args, std::ostream& out, std::ostream& err);`
  - `int main_entry(int argc, char** argv, std::ostream& out, std::ostream& err);`
- Exit codes:
  - `0`: ok
  - `1`: usage error
  - `2`: file/ELF input error
  - `3`: disassembly or resolver error
- `Arguments::show_bytes` is set by `--show-bytes` and restores raw instruction bytes in text output.

## Version: `include/roe/version.hpp`

- Namespace: `roe`
- Constants:
  - `version_major`
  - `version_minor`
  - `version_patch`
  - `version_string`
  - `program_name`
