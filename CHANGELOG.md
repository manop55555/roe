<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to `roe` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com); this project uses
[Semantic Versioning](https://semver.org).

## [1.0.0] — 2026-05-28

First release. `roe` is a command-line disassembler that aims to be readable by
default, answering the LKML *"objdump output is just horrendous, not fit for
humans"* complaints (29 Oct 2025).

### Added

- **Real Mach-O and PE/COFF parsing.** Mach-O (x86-64 + ARM64, thin and fat)
  and PE/COFF (x86/x86-64/ARM64, `.exe` and `.dll`) are now parsed directly, not
  just detected; previously only ELF was parsed. Static archives are still
  detected but not parsed.
- **Disassemble by address or range** on stripped binaries: `--addr <hex>`
  walks from an address to a return/terminal or a cap, and `--range
  <start>-<end>` covers an inclusive range.
- **File inspection views** that need no disassembly: `--headers` (format,
  architecture, type, entry point, endianness), `--sections` (name, size,
  permissions, offset), `--segments` (ELF program headers / Mach-O load commands
  / PE data directories), `--imports` (grouped by library), and `--exports`.
- **Hex dump** with `--hex [section]` of a named section or of an `--addr` /
  `--range` window, with `--bytes <n>` controlling the `--hex --addr` length.
- **Function-level diff** with `--diff <other>` (added / removed / changed /
  unchanged); with a symbol argument it emits a per-function unified diff.
  Supports `--json` for the summary.
- **Disassemble raw bytes from stdin** with `--raw-bytes` (requires `--arch`),
  auto-detecting hex text vs raw binary (`--hex-input` forces hex) with an
  optional `--base <hex>` load address.
- **String extraction with cross-references** via `--strings`: printable runs of
  at least `--min-len` bytes (4 by default), each shown with the instruction
  that references it or `(no xref found)`.
- **Fuzzy symbol search** with `--find <pattern>`: a case-insensitive search
  across symtab, dynsym, imports, exports, and demangled names, each match
  tagged `[symtab]`/`[dynsym]`/`[import]`/`[export]`.
- **Pipeline ergonomics**: `--quiet`/`-q` for bare, undecorated output and
  `--verbose`/`-v` for extra context (raw bytes, resolver provenance), with
  `-v -v` adding debug diagnostics on stderr.
- **Readable disassembly** of ELF binaries: relocations resolved to symbol
  names, inline branch-target previews (`je 0x35 → [L1: ...]`), generated labels
  at jump targets, preserved addresses, and raw bytes off by default.
- **String-reference annotation** for x86 RIP-relative/absolute loads and ARM64
  ADRP+ADD/LDR pairs (`lea rdi, [rip + 0xe51]  ; "hello: %d\n"`).
- **Multi-architecture disassembly** via Capstone: x86, x86-64, ARM, Thumb,
  AArch64, RISC-V 32/64, MIPS 32/64 (LE/BE), PowerPC 32/64 (LE/BE), with per-ISA
  branch classification. x86-64 and AArch64 are the fully verified targets.
- **Symbol resolution** including PLT/GOT, plus **C++ (Itanium)** and **Rust
  (legacy + v0)** demangling.
- **Source interleaving** (`--source`) from a built-in DWARF `.debug_line`
  reader (versions 2–5).
- **Analysis features**: `--grep`, `--calls`, `--contains`, `--xref`, `--stats`.
- **Workflow**: `--watch` (inotify), `$PAGER` integration, a TOML config file,
  and JSON output (`--json`) for every command.
- **Format-neutral `BinaryFile` interface** with an ELF backend; Mach-O,
  PE/COFF, and static archives are detected and reported honestly.
- **CLI**: grouped `--help` with topics, `--version` with build/Capstone/arch
  info, exit codes (0/1/2/3), and bash/zsh/fish/PowerShell completions.
- **Manual** (`man roe`), Apache-2.0 license, NOTICE, DWARF/Capstone attribution.
- **Distribution**: `install.sh`, a multi-stage Docker image, `cmake --install`,
  and Debian/RPM/Arch/Alpine/Nix/Homebrew/Scoop manifests.
- **Quality**: Catch2 test suite (≥80% line coverage), ASan/UBSan-clean,
  libFuzzer harnesses (ELF, Mach-O, and PE parsers plus the full loader), and
  CI workflows.

### Security

- **Hardened the PE parser against resource exhaustion.** Import-thunk iteration
  and the export-name count are now bounded (65 536 symbols per object), so a
  malformed PE cannot force unbounded parsing work. Surfaced by the libFuzzer PE
  harness and locked in place by a regression seed and a unit test.

[1.0.0]: https://github.com/USER/roe/releases/tag/v1.0.0
