# roe v1 Architecture

## Goal

`roe` is a format-neutral disassembler focused on readable output: preserved
addresses, resolved symbols and relocations, inline branch previews, source
interleaving, search, xrefs, and machine-readable JSON. v1 keeps the v0.1 CLI
behavior and expands the input matrix to ELF, Mach-O, PE/COFF, and static
archives across the required CPU architectures.

The user-facing workflows are:

- `roe <file>` lists functions.
- `roe <file> <symbol>` disassembles one function.
- `roe <file> --section .text` disassembles one executable section.
- `roe <file> -D` or `roe <file> --all` disassembles every executable section.
- `roe <file> --grep PATTERN`, `--calls SYMBOL`, and `--contains STRING` filter function lists.
- `roe <file> --xref SYMBOL` prints cross-references.
- `roe <file> --stats` prints function statistics.
- `roe <file> <symbol> --source` interleaves source where debug information exists.
- `roe <file> <symbol> --json` emits the documented JSON schema.
- `roe --help`, `roe --help <topic>`, `roe --completions <shell>`, and `roe --version` render discoverability output.

## Format-Neutral Model

v1 introduces `roe::binary::BinaryFile` in `include/roe/binary.hpp` above the
existing `roe::elf::File`. Parser modules own format-specific details but must
expose a normalized `binary::FileView` so disassembly, resolver, formatter,
features, and CLI code do not branch on ELF, Mach-O, PE, or archive internals.

Key types:

- `binary::FileView`: one input file, detected by magic bytes, containing one or more objects.
- `binary::Object`: one architecture slice or archive member with architecture, endianness, entry point, sections, symbols, relocations, strings, and stripped status.
- `binary::Section`: normalized executable/data/debug/string section metadata.
- `binary::Symbol`: normalized static, dynamic, imported, exported, and synthetic symbols.
- `binary::Relocation`: normalized relocation/reference metadata, including PLT/import stubs.
- `binary::StringLiteral`: read-only string data for annotation and `--contains`.
- `binary::BinaryFile`: polymorphic adapter that returns the `FileView` and owned bytes for a selected section.

### Migration Path

Existing v0.1 ELF APIs remain valid:

- `elf::parse_file`
- `elf::parse_bytes`
- `elf::find_section`
- `elf::function_symbols`
- `elf::find_symbol`
- `elf::section_bytes`

ELF v1 work adds adapter entry points:

- `elf::open_file`
- `elf::open_bytes`

New v1 CLI flows should call `binary::load_file` / `binary::load_bytes` and then
operate on `binary::BinaryFile`. Existing tests may continue to exercise
`elf::File` directly until migrated. The ELF adapter is responsible for copying
or translating ELF metadata into the normalized model without weakening ELF
validation.

## Magic-Byte Detection

Format selection is based only on bytes, never file extension.

Detection ownership:

- `binary::detect_format`: identifies ELF, Mach-O, Mach-O fat, PE/COFF, archive, or unknown.
- `binary::load_file`: reads the first bytes, dispatches to the matching parser, and preserves the first 16 bytes for diagnostics.
- Unknown input returns `ErrorCode::UnsupportedFormat` with a first-16-byte hex dump from `binary::first_bytes_hex`.

Parser modules may perform deeper validation after dispatch, but they must not
accept a file because of its extension.

## Module Boundaries

### `roe::binary`

Owned by `include/roe/binary.hpp`; implementation can live in `src/binary/` or
the CLI/parser integration area if needed by the lead.

Responsibilities:

- Magic-byte detection and parser dispatch.
- Normalized format, architecture, object, section, symbol, relocation, and string models.
- The `BinaryFile` adapter interface.
- Shared helpers for object, section, and function lookup.

Non-responsibilities:

- Format-specific parsing.
- Disassembly.
- Rendering.

### `roe::elf`

Owned by `src/elf/` and `include/roe/elf.hpp`.

Responsibilities:

- Parse ELF32 and ELF64, little and big endian.
- Support x86, x86-64, ARM32, AArch64, RISC-V, MIPS, and PowerPC machine IDs.
- Parse headers, sections, segments, symbols, string tables, relocations, PLT/GOT metadata, and stripped status.
- Expose the legacy `elf::File` API and the v1 `BinaryFile` adapter.
- Reject malformed input without crashing.

### `roe::macho`

Owned by `src/macho/` and `include/roe/macho.hpp`.

Responsibilities:

- Parse 32/64-bit Mach-O headers where needed for supported v1 targets.
- Support x86-64, ARM64, and fat/universal binaries containing multiple architecture slices.
- Parse segments, sections, symbol tables, relocation metadata, string sections, and DWARF locations needed by other modules.
- Expose `BinaryFile` adapters.

### `roe::pe`

Owned by `src/pe/` and `include/roe/pe.hpp`.

Responsibilities:

- Parse PE/COFF `.exe`, `.dll`, and object files.
- Support x86, x86-64, ARM32, and ARM64.
- Parse section tables, COFF symbols, import tables, export tables, relocations, `.rdata` strings, and PDB lookup paths.
- Expose `BinaryFile` adapters.

### `roe::archive`

Owned by `src/archive/` and `include/roe/archive.hpp`.

Responsibilities:

- Parse Unix archives, COFF archives, `.a`, `.lib`, and object collections.
- Preserve member names and bytes.
- Dispatch archive members through ELF, Mach-O, or PE/COFF parsers and expose each member as a `binary::Object`.

### `roe::disasm`

Owned by `src/disasm/`, `src/disasm/arch/`, and `include/roe/disasm.hpp`.

Responsibilities:

- Integrate Capstone for every v1 architecture.
- Decode x86, x86-64, ARM32 ARM mode, ARM32 Thumb mode, AArch64, RISC-V 32/64, MIPS 32/64 little and big endian, and PowerPC 32/64 little and big endian.
- Classify unconditional jumps, conditional branches, calls, indirect calls/jumps, returns, loops, and traps per ISA.
- Preserve addresses and raw bytes in instruction records.
- Accept `binary::SectionBytes` and normalized architecture options.

Non-responsibilities:

- Symbol lookup.
- Formatting labels/previews.

### `roe::resolver`

Owned by `src/resolver/` and `include/roe/resolver.hpp`.

Responsibilities:

- Build lookup indexes from `binary::BinaryFile`.
- Resolve symbols, nearest symbols, relocations, imports, exports, PLT/GOT stubs, and archive-member symbols.
- Demangle C++ Itanium names, C++ MSVC names, Rust legacy names, and Rust v0 names.
- Annotate decoded instructions with symbols, relocation references, branch target symbols, and string references.

### `roe::debug`

Owned by `src/debug/` and `include/roe/debug.hpp`.

Responsibilities:

- Read DWARF from ELF and Mach-O.
- Locate PDB metadata for PE and read source locations when available.
- Return a single graceful fallback message when no debug information exists.
- Interleave source locations with decoded instructions for `--source`.

### `roe::features`

Owned by `src/features/` and `include/roe/features.hpp`.

Responsibilities:

- Search/filter by regex, callee, and string literal.
- Compute xrefs.
- Annotate string references from `.rodata`, `__cstring`, and `.rdata`.
- Compute function statistics: size, basic blocks, branch count, and max nesting depth.
- Provide data models consumed by text and JSON formatters.

### `roe::watcher`

Owned by `src/watcher/` and `include/roe/watcher.hpp`.

Responsibilities:

- Provide a single file-change API for watch mode.
- Use inotify on Linux, kqueue on macOS/BSD, and ReadDirectoryChangesW on Windows.
- Debounce changes and report deleted/replaced files.

### `roe::format`

Owned by `src/format/` and `include/roe/format.hpp`.

Responsibilities:

- Render function lists, disassembly, xrefs, stats, sections, source output, JSON, errors, help, completions, and version output.
- Generate stable branch labels (`L1`, `L2`, ...).
- Render branch target previews inline, for example `je 0x35 → [L1: xor eax, eax]`.
- Keep raw instruction bytes hidden unless `--show-bytes` is set.
- Apply color/pager decisions from options and environment.

### `roe::cli`

Owned by `src/cli/`, `src/main.cpp`, and `include/roe/cli.hpp`.

Responsibilities:

- Parse all v1 flags.
- Apply config-file defaults and CLI overrides.
- Select object/architecture when needed.
- Dispatch to binary parsing, resolver, disassembly, debug, feature, and formatting workflows.
- Map exit codes: `0` ok, `1` usage, `2` file/input error, `3` disassembly/resolver error.

## Data Flow

### Function list

1. CLI parses `roe <file>` plus filters/config.
2. `binary::load_file` detects the format and returns a `BinaryFile`.
3. `binary::primary_object` selects the default architecture slice or archive member.
4. `resolver::build_index` prepares demangled names, import/PLT symbols, relocations, and strings.
5. `features` filters functions if requested.
6. `format::render_function_list` prints text or JSON.

### Single function disassembly

1. CLI parses `roe <file> <symbol>`.
2. `binary::load_file` returns a `BinaryFile`.
3. `binary::find_symbol` selects the function.
4. `disasm::options_for` maps `binary::Architecture` to Capstone mode.
5. `disasm::disassemble_function` decodes bytes from the selected object.
6. `resolver::annotate` adds symbols, relocations, imports, PLT stubs, and branch target symbols.
7. `features::annotate_string_references` adds string comments.
8. `debug::interleave` adds source lines when `--source` is set.
9. `format::render_disassembly` or JSON rendering preserves addresses and emits labels/previews.

### Whole-section and all-section disassembly

1. CLI parses `--section <name>` or `-D` / `--all`.
2. The selected `BinaryFile` returns owned section bytes.
3. Disassembly, resolver annotation, string annotation, source interleaving, and formatting run as above.

### Xref, calls, contains, and stats

1. CLI loads and indexes the selected object.
2. Disassembly iterates function bodies needed for the query.
3. `features` computes xrefs, stats, or filtered function sets.
4. `format` renders text or JSON with a stable schema.

## Fuzzing

Every parser that accepts untrusted bytes has a dedicated fuzzer:

- `fuzz/elf_parser_fuzzer.cpp` - the ELF parser and its metadata accessors.
- `fuzz/macho_parser_fuzzer.cpp` - the Mach-O parser.
- `fuzz/pe_parser_fuzzer.cpp` - the PE/COFF parser.
- `fuzz/binary_loader_fuzzer.cpp` - format detection and the loader path.

Fuzzers parse from owned byte vectors, exercise metadata accessors and adapter
creation, and never shell out or depend on host toolchains.

## Error Handling

All public module entry points return `roe::Result<T>` or `roe::Result<void>`
for expected failures. Parser errors are normal outcomes for malformed input and
must return structured `Error` values, not crashes or uncaught exceptions.

Unknown format errors must include:

- `ErrorCode::UnsupportedFormat`
- source name when available
- first 16 bytes as hex

## Rationale

- A normalized `BinaryFile` boundary prevents ELF assumptions from leaking into disassembly, resolver, formatter, and CLI code.
- Parser-specific models remain available so each parser can validate deeply without losing format detail.
- Section bytes are returned as owned data in the v1 model so archive members and fat binary slices do not expose fragile iterator lifetimes.
- Formatting owns labels and previews because labels are presentation policy, not disassembly facts.
- Parser fuzzers are separate because ELF, Mach-O, PE/COFF, and archive structures have different trust boundaries.
