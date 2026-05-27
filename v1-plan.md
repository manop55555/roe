# roe v1.0.0 Plan

## Release Rule

Ship directly as `v1.0.0` only after every command in section G of the build order passes with real outputs. Do not weaken checks, silently skip architecture tests, or document unverified behavior.

## A. Architecture Coverage

- Extend Capstone-backed disassembly for x86, x86-64, ARM32 ARM mode, ARM32 Thumb mode, AArch64, RISC-V 32/64, MIPS 32/64 little and big endian, PowerPC 32/64 little and big endian.
- Add branch classification per ISA: unconditional branches, conditional branches, calls, indirect calls/jumps, returns, loops where applicable.
- Preserve v0.1 behavior: labels for in-function targets, inline previews, symbolized cross-function calls, PLT names.
- Add `scripts/test-arch.sh` with loud missing-toolchain failures.
- Add one real compiled fixture per architecture when the host toolchain exists.

## B. Executable Formats

- Introduce a format-neutral `BinaryFile` model above `elf::File`.
- Add magic-byte detection with first-16-byte hex error for unknown formats.
- Keep ELF parser and adapt it into `BinaryFile`.
- Add Mach-O parser in `src/macho/`, including x86-64, ARM64, and fat/universal binaries.
- Add PE/COFF parser in `src/pe/`, including x86, x86-64, ARM32, ARM64, `.exe`, and `.dll`.
- Add static archive parser in `src/archive/` for `.a`, `.lib`, and object collections.
- Add fuzz harnesses for ELF, Mach-O, PE, and archive parsers.

## C. Features

- `--source`: DWARF source interleaving for ELF/Mach-O and PDB lookup path for PE, with one-line graceful fallback.
- `-D` / `--all`: disassemble every executable section.
- C++ demangling: verify real ELF/Mach-O Itanium symbols and PE/MSVC names.
- Rust demangling: legacy `_ZN...E` and v0 `_RNv...` symbols.
- Filters: `--grep PATTERN`, `--calls SYMBOL`, `--contains STRING`.
- Xrefs: `--xref SYMBOL` with caller function and instruction address.
- String references: annotate `.rodata`, `__cstring`, and `.rdata` literals, truncated to 64 chars with ellipsis.
- Stats: `--stats` prints per-function size, basic block count, branch count, max nesting depth.
- Watch mode in `src/watcher/` using platform watcher backends.
- Pager integration with `$PAGER`, `NO_PAGER`, and `--no-pager`.
- Config file loader for Linux, macOS, and Windows paths with CLI override precedence.
- Shell completions for bash, zsh, fish, and PowerShell.
- JSON output for disassembly, function list, xref, stats, and section list with documented schema.

## D. Help And Manual

- Rewrite `--help` with banner, categories, every flag, five real examples, `man roe`, and GitHub URL.
- Add `--help <topic>` for `usage`, `formats`, `arches`, `examples`, `config`, and `json`.
- Add `docs/roe.1`; verify with `groff -man -Tutf8 -w all`.
- Extend `--version` with build hash, build date, Capstone version, supported architectures, and supported formats.

## E. License And Legal

- Add Apache-2.0 `LICENSE`.
- Add `NOTICE` with third-party attributions and Capstone BSD-3-Clause license text.
- Add SPDX headers to every source/header/script where appropriate.
- Add `docs/LICENSING.md`.
- Add `CONTRIBUTING.md` with DCO sign-off requirement.
- Set CMake project license metadata and include legal files in install/release artifacts.

## F. Installation And Distribution

- Add idempotent `install.sh` that verifies SHA-256 before installing.
- Make `cmake --install build --prefix /usr/local` install binary, man page, completions, LICENSE, and NOTICE.
- Add multi-stage `Dockerfile` with final image target below 20 MB.
- Add packaging manifests for Debian, RPM, Arch, Alpine, Homebrew, Scoop, and Nix.
- Add GitHub Actions workflows: `ci.yml`, `release.yml`, `docker.yml`.

## G. Verification

- Build clean with zero warning/error output.
- Sanitizer build and full tests pass.
- `scripts/fuzz.sh` runs ELF, Mach-O, PE, archive fuzzers for 1M iterations each.
- `scripts/coverage.sh` reports at least 80% `src/` line coverage.
- Help, topic help, version, man page, architecture scripts, format fixture commands, feature spot checks, install, Docker, legal checks, and README accuracy all pass exactly as specified.

## Agent Integration Order

1. Architect updates module contracts and `BinaryFile` interface.
2. Parser agents add Mach-O, PE, archive, and ELF adaptation behind `BinaryFile`.
3. Disassembly agents add Capstone architecture modes and branch classifiers.
4. Resolver/feature/format/CLI agents add v1 workflows.
5. Help/legal/packaging agents add distribution and documentation.
6. Test/security agents add fixtures, fuzzing, coverage, README checks, and section G scripts.
