<!-- SPDX-License-Identifier: Apache-2.0 -->
# roe — a disassembler fit for humans

```
roe v1.0.0 — a disassembler fit for humans

           (             )
            `--(_   _)--'
                 Y-Y
                /@@ \
               /     \
               `--'.  \             ,
                   |   `.__________/)

resolve relocations · preview branch targets · clean output
```

`roe` is a command-line disassembler for **ELF, Mach-O, PE/COFF, and static
archive** binaries that aims to be readable by default. Point it at a binary and
a function name; it resolves relocations to symbol names, previews where each
branch goes, labels jump targets, and annotates string references — without a
wall of unmemorable flags.

## Why

On the LKML thread *"odd objtool 'unreachable instruction' warning"* (29 Oct
2025), Linus Torvalds laid out why `objdump` is painful to read:

1. the flags are unmemorable;
2. they trade off readability against information;
3. **relocations show up as raw addresses, not symbol names** — *"objdump output
   is just horrendous, not fit for humans"*;
4. there is no way to preview a jump or call target without scrolling; and
5. nobody had built a general-purpose CLI alternative.

`roe` is that alternative. It is general-purpose: it works on any ELF, Mach-O,
PE, or static archive — not just `vmlinux.o`.

## The difference

Disassembling `main`, which loads a format string and calls `printf`:

**objdump**

```
000000000000119c <main>:
    119c:	sub    $0x8,%rsp
    11a5:	call   1160 <compute>
    11ac:	lea    0xe51(%rip),%rdi        # 2004 <_IO_stdin_used+0x4>
    11b8:	call   1030 <printf@plt>
    11c6:	ret
```

**roe**

```
0x000000000000119c: sub rsp, 8  ; sym main
0x00000000000011a5: call compute  ; @0x1160
0x00000000000011ac: lea rdi, [rip + 0xe51]  ; "compute(20) = %d\n"
0x00000000000011b8: call printf@plt  ; @0x1030
0x00000000000011c6: ret
```

objdump points the `lea` at `# 2004 <_IO_stdin_used+0x4>` — a raw address. `roe`
shows the **actual string** the code loads: `"compute(20) = %d\n"`.

## Branch previews and labels

```
$ roe ./demo compute
0x0000000000001160: test edi, edi  ; sym compute
0x0000000000001162: jle 0x1196 → [L2: mov eax, 0]
0x0000000000001164: mov ecx, 1
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

Every conditional branch shows its destination inline (`→ [L2: ...]`), and jump
targets get short labels (`L1:`, `L2:`) so you can follow the control flow
without scrolling or doing hex arithmetic.

## Quick start

```sh
# Build a tiny example
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

roe demo                 # list functions
roe demo main            # disassemble one function, resolved
roe demo --section .text # disassemble a section
roe demo --all           # every executable section
```

More:

```sh
roe demo main --json | jq .       # machine-readable output
roe demo main --source            # interleave source lines (needs -g)
roe demo main --show-bytes        # include raw instruction bytes
roe libfoo.so --grep '::'         # C++ methods, demangled
roe demo --calls printf           # functions that call printf
roe demo --xref printf            # every call site of printf
roe demo --stats                  # per-function size/blocks/branches/depth
roe demo main --watch             # re-run on every file change
```

`--stats` and `--xref`, for the example above:

```
$ roe demo --stats
      size  blocks  branch  depth  function
        43       1       2      0  main
        60       5       2      2  compute

$ roe demo --xref printf
References to printf (1)
0x00000000000011b8  main  call printf@plt
```

## Features

- **Resolved relocations** — calls and data references show symbol names and
  resolved strings, not raw offsets.
- **Inline branch previews** (`je 0x35 → [L1: xor eax, eax]`) and **labels** at
  jump targets.
- **String-reference annotation** — `lea rdi, [rip + 0xe51]  ; "hello: %d\n"`.
- **C++ (Itanium) and Rust (legacy + v0) demangling.**
- **Source interleaving** (`--source`) from DWARF line info.
- **Search/filter** — `--grep`, `--calls`, `--contains`; cross-references
  (`--xref`); per-function statistics (`--stats`).
- **JSON output** for every command (`--json`), documented in
  [`docs/JSON_SCHEMA.md`](docs/JSON_SCHEMA.md).
- **Watch mode** (`--watch`), a pager (`$PAGER`), and a config file
  ([`docs/CONFIG.md`](docs/CONFIG.md)).
- **Sane defaults**: addresses preserved, raw bytes off, color on a TTY, paged
  when long. `NO_COLOR`, `NO_PAGER`, `--no-color`, `--no-pager` all respected.

## Architecture and format support

Disassembly is backed by [Capstone](https://www.capstone-engine.org). All of
these decode, classify branches, and resolve targets:

> x86, x86-64, ARM, Thumb, AArch64, RISC-V 32/64, MIPS 32/64 (LE/BE),
> PowerPC 32/64 (LE/BE).

**x86-64 and AArch64 are the fully verified, production targets** — real
cross-compiled fixtures and every feature, including ARM64 ADRP+ADD string
references. The others are supported and unit-tested against known encodings;
ARM/Thumb mode is selected with `--arch thumb` when needed.

This release **parses ELF**. Mach-O, PE/COFF, and static archives are detected
by magic bytes and reported clearly rather than mis-parsed. The polymorphic
`BinaryFile` interface (see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)) is in
place so additional backends slot in without touching disasm, resolver, or
output code.

## Install

**One-line script** (downloads a release binary, verifies its SHA-256):

```sh
curl -fsSL https://raw.githubusercontent.com/USER/roe/main/install.sh | sh
```

**From source** (needs CMake ≥ 3.16, a C++17 compiler, and Capstone ≥ 5):

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
sudo cmake --install build --prefix /usr/local   # binary, man page, completions
```

**Docker:**

```sh
docker run --rm -v "$PWD:/data" ghcr.io/USER/roe /data/demo main
```

**Packages:** Debian/Ubuntu (`.deb`), Fedora/RHEL (`.rpm`), Arch (`PKGBUILD`),
Alpine (`APKBUILD`), Nix, Homebrew, and Scoop manifests live in
[`packaging/`](packaging/).

**Shell completions:**

```sh
roe --completions bash > /etc/bash_completion.d/roe   # or zsh | fish | powershell
```

## Help

```sh
roe --help              # grouped flags, examples, and pointers
roe --help arches       # focused topics: usage formats arches examples config json
man roe                 # full manual
roe --version           # version, build, Capstone version, arches, formats
```

> The repository placeholder `USER` in install/Docker/package commands is
> substituted with the real GitHub owner at release time.

## Documentation

| Document | Contents |
| --- | --- |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | modules, the `BinaryFile` interface, data flow |
| [`docs/INTERFACES.md`](docs/INTERFACES.md) | the contract each module exposes |
| [`docs/DECISIONS.md`](docs/DECISIONS.md) | one-line rationale per non-obvious decision |
| [`docs/CONFIG.md`](docs/CONFIG.md) | every config key |
| [`docs/JSON_SCHEMA.md`](docs/JSON_SCHEMA.md) | the stable JSON output schema |
| [`docs/LICENSING.md`](docs/LICENSING.md) | project and dependency licenses |
| [`SECURITY.md`](SECURITY.md) | threat model, fuzzing, reporting |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | how to contribute (DCO sign-off) |

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE). Bundles Capstone
(BSD-3-Clause); the test suite uses Catch2 (BSL-1.0).
