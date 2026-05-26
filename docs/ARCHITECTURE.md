# roe Architecture

## Goal

`roe` is a small ELF disassembly tool focused on preserving addresses, resolving symbols and relocations, and showing branch target previews inline. The command line surface is intentionally narrow:

- `roe <file>` lists functions.
- `roe <file> <symbol>` disassembles one function.
- `roe <file> --section .text` disassembles a full section.
- `roe <file> <symbol> --no-color` produces pipe-friendly text.
- `roe <file> <symbol> --json` produces machine-readable output.
- `roe --help` and `roe --version` render banner/help output.

## Module Boundaries

### `roe::elf`

Owned by `src/elf/` and `include/roe/elf.hpp`.

Responsibilities:

- Parse ELF32 and ELF64 files.
- Support little-endian and big-endian encodings.
- Parse headers, sections, segments, symbols, string tables, and relocations.
- Preserve section bytes needed by disassembly.
- Return structured `Result<T>` failures for malformed files.

Non-responsibilities:

- Disassembly.
- Symbol demangling.
- User-facing formatting.

### `roe::disasm`

Owned by `src/disasm/` and `include/roe/disasm.hpp`.

Responsibilities:

- Integrate Capstone.
- Iterate instructions for x86-64 first, arm64 later.
- Detect branches, calls, returns, and conditional jumps.
- Resolve direct branch targets within the current instruction stream.
- Expose instruction records with preserved addresses and raw bytes.

Non-responsibilities:

- ELF parsing.
- Relocation joining.
- ANSI colors or JSON.

### `roe::resolver`

Owned by `src/resolver/` and `include/roe/resolver.hpp`.

Responsibilities:

- Join relocation entries with ELF symbols.
- Build address-to-symbol indexes.
- Resolve PLT/GOT-style references where ELF metadata permits it.
- Demangle C++ names.
- Provide names suitable for disassembly annotations.

Non-responsibilities:

- Parsing raw ELF structures.
- Producing final text or JSON.

### `roe::format`

Owned by `src/format/` and `include/roe/format.hpp`.

Responsibilities:

- Render function lists, disassemblies, errors, help, version, and JSON output.
- Generate stable branch labels (`L1`, `L2`, ...).
- Render branch target previews inline, for example `je 0x35 → [L1: xor eax, eax]`.
- Apply or suppress ANSI color based on CLI options, pipe detection, and `NO_COLOR`.

Non-responsibilities:

- Command line parsing.
- Disassembly or relocation logic.

### `roe::cli`

Owned by `src/cli/`, `src/main.cpp`, and `include/roe/cli.hpp`.

Responsibilities:

- Parse command line arguments.
- Select the workflow.
- Map errors to exit codes: `0` ok, `1` usage, `2` file error, `3` disassembly error.
- Keep user-facing diagnostics clear without requiring documentation.

Non-responsibilities:

- Parsing ELF internals.
- Formatting final disassembly beyond calling `roe::format`.

### Shared Core

Owned by public headers under `include/roe/`.

Responsibilities:

- `roe::Error`, `roe::ErrorCode`, and `roe::Result<T>`.
- Version constants.
- Small value types used across module boundaries.

## Data Flow

### Function list

1. `cli::parse_args` identifies `roe <file>`.
2. `elf::parse_file` returns an `elf::File`.
3. `resolver::build_index` prepares demangled names and address lookup.
4. `format::render_function_list` prints all known function symbols.

### Single function disassembly

1. `cli::parse_args` identifies `roe <file> <symbol>`.
2. `elf::parse_file` loads metadata and section bytes.
3. `resolver::build_index` finds the requested symbol and relocation references.
4. `disasm::disassemble_function` disassembles the symbol's range.
5. `resolver::annotate` adds symbol and relocation names to instructions.
6. `format::render_disassembly` generates text or JSON, preserving all addresses.

### Section disassembly

1. `cli::parse_args` identifies `--section`.
2. `elf::parse_file` loads the named section.
3. `disasm::disassemble_section` iterates the full section.
4. `resolver::annotate` adds names where available.
5. `format::render_disassembly` emits text or JSON.

## Error Handling

All public module entry points return `roe::Result<T>` or `roe::Result<void>`. Implementations must not use exceptions for expected control flow. A malformed input file is a normal parser error and must return `ErrorCode::MalformedInput` or a more specific code instead of crashing.

## Rationale

- ELF parsing is isolated because it is the largest untrusted-input surface and must be fuzzed independently.
- Disassembly consumes typed bytes and addresses, not raw files, so Capstone logic stays independent from ELF details.
- Relocation and symbol resolution is separate from both parsing and formatting because it is the main value-add of `roe`.
- Formatting owns labels and previews so presentation decisions do not leak into the disassembler.
- CLI is thin to keep workflow orchestration testable without invoking `main`.

## Initial Directory Ownership

- `docs/`, `CMakeLists.txt`, `include/roe/`: architecture agent.
- `src/elf/`, `include/roe/elf.hpp`: ELF parser agent.
- `src/disasm/`, `include/roe/disasm.hpp`: disassembly agent.
- `src/resolver/`, `include/roe/resolver.hpp`: resolver agent.
- `src/format/`, `include/roe/format.hpp`: formatting agent.
- `src/cli/`, `src/main.cpp`, `include/roe/cli.hpp`: CLI agent.
- `tests/`: test agent.
- `fuzz/`, `SECURITY.md`: security agent.
