<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to `roe` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com); this project uses
[Semantic Versioning](https://semver.org).

## [1.0.0] — 2026-05-27

First release. `roe` is a command-line disassembler that aims to be readable by
default, answering the LKML *"objdump output is just horrendous, not fit for
humans"* complaints (29 Oct 2025).

### Added

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
  libFuzzer harnesses (ELF parser and full pipeline), and CI workflows.

[1.0.0]: https://github.com/USER/roe/releases/tag/v1.0.0
