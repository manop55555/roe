<!-- SPDX-License-Identifier: Apache-2.0 -->
# roe

```
roe v1.0.0 - a disassembler fit for humans

           (             )
            `--(_   _)--'
                 Y-Y
                /@@ \
               /     \
               `--'.  \             ,
                   |   `.__________/)

resolve relocations · preview branch targets · clean output
```

[![CI](https://github.com/manop55555/roe/actions/workflows/ci.yml/badge.svg)](https://github.com/manop55555/roe/actions/workflows/ci.yml)
[![Docker](https://github.com/manop55555/roe/actions/workflows/docker.yml/badge.svg)](https://github.com/manop55555/roe/actions/workflows/docker.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![Release](https://img.shields.io/badge/release-v1.0.0-blue.svg)](https://github.com/manop55555/roe/releases)

## Overview

roe is a command-line disassembler for ELF, Mach-O, PE/COFF, and static archive
binaries. It resolves relocations to symbol names, names call and branch
targets, previews where each branch goes inline, labels jump targets, and
annotates the strings that code loads - so a function reads like code, not a
wall of raw addresses. Disassembly is backed by Capstone; the binary is a single
native executable that links only libc and Capstone, makes no network calls, and
never executes the binaries it inspects.

The same function, `main`, which loads a format string and calls `printf`.

objdump (`objdump --disassemble=main -d demo`):

```
000000000000119c <main>:
    119c:	48 83 ec 08          	sub    $0x8,%rsp
    11a0:	bf 14 00 00 00       	mov    $0x14,%edi
    11a5:	e8 b6 ff ff ff       	call   1160 <compute>
    11aa:	89 c6                	mov    %eax,%esi
    11ac:	48 8d 3d 51 0e 00 00 	lea    0xe51(%rip),%rdi        # 2004 <_IO_stdin_used+0x4>
    11b3:	b8 00 00 00 00       	mov    $0x0,%eax
    11b8:	e8 73 fe ff ff       	call   1030 <printf@plt>
    11bd:	b8 00 00 00 00       	mov    $0x0,%eax
    11c2:	48 83 c4 08          	add    $0x8,%rsp
    11c6:	c3                   	ret
```

roe (`roe demo main`):

```
0x000000000000119c: sub rsp, 8  ; sym main
0x00000000000011a0: mov edi, 0x14
0x00000000000011a5: call compute  ; @0x1160
0x00000000000011aa: mov esi, eax
0x00000000000011ac: lea rdi, [rip + 0xe51]  ; "compute(20) = %d\n"
0x00000000000011b3: mov eax, 0
0x00000000000011b8: call printf@plt  ; @0x1030
0x00000000000011bd: mov eax, 0
0x00000000000011c2: add rsp, 8
0x00000000000011c6: ret
```

Where objdump prints the `lea` target as a raw address (`# 2004 <_IO_stdin_used+0x4>`),
roe shows the actual string the code loads: `"compute(20) = %d\n"`.

## Contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Examples](#examples)
- [Supported formats and architectures](#supported-formats-and-architectures)
- [Security](#security)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)
- [Maintainer](#maintainer)

## Installation

Build from source. This is the path that works today; it needs CMake >= 3.16, a
C++17 compiler, and Capstone >= 5:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
sudo cmake --install build --prefix /usr/local   # binary, man page, license files
```

After install, the tool is on your PATH as `roe`:

```bash
roe --version
```

Pre-built binaries, a Docker image (`ghcr.io/manop55555/roe`), and the
Debian/RPM/Arch/Alpine/Nix/Homebrew/Scoop manifests in [packaging/](packaging/)
are published with each GitHub release. The one-line installer downloads the
latest release binary and verifies its SHA-256:

```bash
curl -fsSL https://raw.githubusercontent.com/manop55555/roe/main/install.sh | sh
```

Shell completions for bash, zsh, fish, and PowerShell:

```bash
roe --completions bash > /etc/bash_completion.d/roe   # or: zsh | fish | powershell
```

## Uninstall

Remove `roe` with the method that matches how you installed it.

**One-line installer or a hand-copied binary.** The installer drops the binary in
`/usr/local/bin` when that is writable, otherwise in `~/.local/bin`, so remove it from
wherever it landed (check both if unsure — a stale copy in one can shadow the other on
your `PATH`):

```bash
sudo rm -f /usr/local/bin/roe   # system-wide install
rm -f ~/.local/bin/roe          # per-user install
```

**Built and installed with CMake.** Remove exactly what the install recorded:

```bash
sudo xargs rm -v < build/install_manifest.txt
```

If the manifest is gone, delete the files by hand:

```bash
sudo rm -f  /usr/local/bin/roe /usr/local/share/man/man1/roe.1
sudo rm -rf /usr/local/share/doc/roe /usr/local/share/roe /usr/local/include/roe
```

Also delete any shell completion you installed, e.g. `sudo rm -f /etc/bash_completion.d/roe`.

**Package manager or Docker.** Use its own command:

```bash
brew uninstall roe                   # Homebrew
sudo apt remove roe                  # Debian/Ubuntu
sudo dnf remove roe                  # Fedora/RHEL
sudo pacman -R roe                   # Arch
sudo apk del roe                     # Alpine
nix-env -e roe                       # Nix
scoop uninstall roe                  # Windows (Scoop)
docker rmi ghcr.io/manop55555/roe    # Docker image
```

After removing the binary, run `hash -r` (bash) or `rehash` (zsh) so your shell forgets
the old path.

## Quick start

The examples use this `demo`:

```bash
cat > demo.c <<'EOF'
#include <stdio.h>
static int helper(int x) { return x * 3 + 1; }
int compute(int n) {
    int acc = 0;
    for (int i = 0; i < n; i++) { if (i & 1) acc += helper(i); else acc -= i; }
    return acc;
}
int main(void) { printf("compute(20) = %d\n", compute(20)); return 0; }
EOF
cc -O1 -g -o demo demo.c
```

```bash
roe demo                  # list functions with preserved addresses
roe demo main             # disassemble one function, symbols resolved
roe demo --section .text  # disassemble a named section
roe demo --all            # disassemble every executable section
roe demo main --json      # machine-readable output
```

## Usage

```
roe <file>                   list functions with preserved addresses
roe <file> <symbol>          disassemble one function, symbols resolved
roe <file> --section <name>  disassemble a named section
roe <file> --all             disassemble every executable section
```

Input:

| Flag | Description |
|------|-------------|
| `<file>` | object, executable, shared library, or `.o` to inspect |
| `<symbol>` | function name (mangled or demangled) to disassemble |
| `--section <name>` | disassemble a named section, e.g. `.text` |
| `--all`, `-D` | disassemble every executable section |
| `--addr <hex>` | disassemble from an address (stripped-safe) |
| `--range <a>-<b>` | disassemble an inclusive address range |
| `--raw-bytes` | disassemble bytes from stdin (needs `--arch`) |
| `--hex-input` | treat stdin as a hex string (with `--raw-bytes`) |
| `--base <hex>` | base address for `--raw-bytes` (default 0) |
| `--arch <name>` | override/select the architecture (e.g. `thumb`, `riscv64`) |

Inspect:

| Flag | Description |
|------|-------------|
| `--headers` | file header: format, arch, type, entry point |
| `--sections` | sections with size, permissions, offset |
| `--segments` | program headers / load commands / data directories |
| `--imports` | imported symbols grouped by library |
| `--exports` | exported symbols |
| `--hex [section]` | hex + ASCII dump of a section, `--addr`, or `--range` |
| `--bytes <n>` | byte count for `--hex` (clamped to the section; notes on stderr) |
| `--strings` | extract strings with their referencing instruction |
| `--min-len <n>` | minimum string length for `--strings` (default 4) |
| `--find <pattern>` | fuzzy symbol search across all symbol sources |

Filtering and comparison:

| Flag | Description |
|------|-------------|
| `--grep <regex>` | list functions whose name matches a regex |
| `--calls <symbol>` | list functions that call or branch to a symbol |
| `--contains <string>` | list functions whose body references a string |
| `--xref <symbol>` | show every call site of a symbol |
| `--stats` | per-function size, basic blocks, branches, depth |
| `--diff <other>` | function-level diff against another binary |

Output:

| Flag | Description |
|------|-------------|
| `--json` | emit machine-readable JSON |
| `--color <when>` | colorize: `auto` (TTY only, default), `always`, `never` |
| `--no-color` | alias for `--color=never` (`NO_COLOR` also disables) |
| `--show-bytes` | show raw instruction bytes (off by default) |
| `--source` | interleave source lines from debug info |
| `--no-pager` | do not page long output through `$PAGER` |
| `--quiet`, `-q` | bare output for pipelines (no headers/decoration) |
| `--verbose`, `-v` | extra context; `-v -v` adds debug to stderr |

Workflow:

| Flag | Description |
|------|-------------|
| `--watch` | re-run automatically when the file changes |
| `--completions <shell>` | emit a completion script (bash, zsh, fish, powershell) |
| `--help [topic]` | show help; topics: usage formats arches examples config json |
| `--version`, `-V` | show version, build info, arches, and formats |

## Examples

List functions:

```
$ roe demo
Functions in demo
0x0000000000001160        60  compute
0x000000000000119c        43  main
```

Disassemble one function, with branch previews and labels:

```
$ roe demo compute
0x0000000000001160: test edi, edi  ; sym compute
0x0000000000001162: jle 0x1196 → [L2: mov eax, 0]
...
L1:
0x0000000000001180: lea esi, [rax + rcx]
...
0x0000000000001193: jne 0x1180 → [L1: lea esi, [rax + rcx]]
0x0000000000001195: ret
L2:
0x0000000000001196: mov eax, 0
0x000000000000119b: ret
```

Inspect any format:

```bash
roe demo --headers     # format, arch, type, entry point
roe demo --sections    # section table with permissions
roe demo --imports     # imports grouped by library
roe demo --exports     # exported symbols
roe demo --hex .rodata # hex + ASCII dump of a section
```

Disassemble a stripped function by address, or raw bytes from stdin:

```bash
roe demo --addr 0x1160                          # walk from an address
roe demo --range 0x1160-0x119b                  # an inclusive range
echo '55 48 89 e5 c3' | roe --raw-bytes --arch x86_64
```

Search, analyze, and demangle:

```
$ roe demo --xref printf
References to printf (1)
0x00000000000011b8  main  call printf@plt

$ roe sample_cpp.elf64 --find ::
Symbols matching "::" (2)
0x000000000000112a  [symtab]  fixture::Worker::compute(int)
0x000000000000114b  [symtab]  fixture::call_worker(int)
```

`--grep`, `--calls`, `--contains`, and `--stats` filter and summarize function
lists the same way.

Diff two builds of a function:

```
$ roe v2.elf64 changed_fn --diff v1.elf64
diff of changed_fn (v1.elf64 -> v2.elf64)
- lea eax, [rdi + rdi]
+ lea eax, [rdi + rdi*2]
  ret
```

The same commands work across formats - here a Mach-O object and a Windows PE:

```
$ roe sample.macho_x86_64
Functions in sample.macho_x86_64
0x0000000000000000         0  _my_helper [dyn]
0x0000000000000010         0  _my_export [dyn]

$ roe sample.pe_x64 --imports
Imports in sample.pe_x64
  libraries: KERNEL32.dll, msvcrt.dll
  KERNEL32.dll:
    DeleteCriticalSection
    ...
```

Source interleaving (needs `-g`) and watch mode:

```bash
roe demo main --source   # interleave demo.c source lines with instructions
roe demo main --watch    # re-run the disassembly each time demo changes on disk
```

## Supported formats and architectures

| Container | Support |
|-----------|---------|
| ELF (32/64-bit, little/big endian) | parsed: executables, shared objects, `.o` |
| Mach-O (x86-64 and ARM64; thin and fat) | parsed |
| PE/COFF (x86, x86-64, ARM64; `.exe` and `.dll`) | parsed |
| static archive (`.a`) | detected; extract members and inspect them individually |

| Architecture | Status |
|--------------|--------|
| x86, x86-64 | fully verified |
| AArch64 (ARM64) | fully verified |
| ARM, Thumb | supported (use `--arch thumb` for Thumb code) |
| RISC-V 32/64 | supported |
| MIPS 32/64 (LE/BE) | supported |
| PowerPC 32/64 (LE/BE) | supported |

Function symbols come from ELF/Mach-O symbol tables and the PE/COFF symbol table
(falling back to the export table for stripped PEs), so `roe <file> <function>`,
`--find`, `--grep`, `--xref`, and `--stats` work by name across ELF, Mach-O, and
PE.

## Security

roe parses attacker-controlled binaries, so a parser bug is a security issue.
The project is built and tested with that in mind:

| Property | Status |
|----------|--------|
| Memory / UB safety | AddressSanitizer + UndefinedBehaviorSanitizer on every change |
| Parser fuzzing | libFuzzer harnesses for the ELF, Mach-O, and PE/COFF parsers and the loader |
| Test coverage | Catch2 unit and integration suite, ~82% line coverage |
| Inputs | offline only; roe never executes the binaries it inspects |

Report a suspected vulnerability privately through
[GitHub Security Advisories](https://github.com/manop55555/roe/security/advisories/new),
not a public issue. The threat model, fuzzing setup, and hardening notes are in
[SECURITY.md](SECURITY.md).

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - modules, the `BinaryFile` interface, data flow
- [docs/INTERFACES.md](docs/INTERFACES.md) - the contract each module exposes
- [docs/CONFIG.md](docs/CONFIG.md) - every config-file key
- [docs/JSON_SCHEMA.md](docs/JSON_SCHEMA.md) - the JSON output schema
- [docs/DECISIONS.md](docs/DECISIONS.md) - design rationale
- [docs/LICENSING.md](docs/LICENSING.md) - project and dependency licenses
- [CHANGELOG.md](CHANGELOG.md) - release history
- `man roe` - the full manual page

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the build setup, commit conventions,
and the DCO sign-off required on every commit. By participating you agree to the
[Code of Conduct](CODE_OF_CONDUCT.md). Use
[Issues](https://github.com/manop55555/roe/issues) for bug reports.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). roe links
[Capstone](https://www.capstone-engine.org) (BSD-3-Clause); the test suite uses
Catch2 (BSL-1.0), which is not part of the released binary.

## Maintainer

[manop55555](https://github.com/manop55555).
