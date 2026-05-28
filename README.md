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

## What it is

`roe` is a command-line disassembler for **ELF, Mach-O, PE/COFF, and static
archive** binaries. It resolves relocations to symbol names, names call and
branch targets, previews where each branch goes inline, labels jump targets, and
annotates the strings that code loads — so a function reads like code, not a wall
of raw addresses. Point it at a binary and a function name and it prints one
clean, readable listing.

## Why

`objdump` is hard to read: the flags are unmemorable, relocations print as raw
addresses instead of symbol names, and there is no way to preview a jump or call
target without scrolling and doing hex arithmetic. `roe` answers that directly —
it resolves relocations to names, previews branch destinations inline, labels
jump targets, and keeps raw bytes and color off unless you ask. It works on any
ELF, Mach-O, PE, or static archive, not just one kind of file.

## objdump vs roe

The same function, `main`, which loads a format string and calls `printf`:

**objdump** (`objdump --disassemble=main -d demo`)

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

**roe** (`roe demo main`)

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

Where objdump points the `lea` at `# 2004 <_IO_stdin_used+0x4>`, `roe` shows the
actual string the code loads: `"compute(20) = %d\n"`.

## Install

**One-line script** (downloads a release binary and verifies its SHA-256):

```sh
curl -fsSL https://raw.githubusercontent.com/manop55555/roe/main/install.sh | sh
```

**From source** (needs CMake ≥ 3.16, a C++17 compiler, and Capstone ≥ 5):

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
sudo cmake --install build --prefix /usr/local   # binary, man page, completions
```

**Docker:**

```sh
docker run --rm -v "$PWD:/data" ghcr.io/manop55555/roe /data/demo main
```

**Packages:** Debian/Ubuntu (`.deb`), Fedora/RHEL (`.rpm`), Arch (`PKGBUILD`),
Alpine (`APKBUILD`), Nix, Homebrew, and Scoop manifests live in
[`packaging/`](packaging/).

**Shell completions:**

```sh
roe --completions bash > /etc/bash_completion.d/roe   # or: zsh | fish | powershell
```

## Usage

```
roe <file>                   list functions with preserved addresses
roe <file> <symbol>          disassemble one function, symbols resolved
roe <file> --section <name>  disassemble a named section
roe <file> --all             disassemble every executable section
```

**Input**

| Flag | Description |
| --- | --- |
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

**Inspect**

| Flag | Description |
| --- | --- |
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

**Filtering & comparison**

| Flag | Description |
| --- | --- |
| `--grep <regex>` | list functions whose name matches a regex |
| `--calls <symbol>` | list functions that call or branch to a symbol |
| `--contains <string>` | list functions whose body references a string |
| `--xref <symbol>` | show every call site of a symbol |
| `--stats` | per-function size, basic blocks, branches, depth |
| `--diff <other>` | function-level diff against another binary |

**Output**

| Flag | Description |
| --- | --- |
| `--json` | emit machine-readable JSON |
| `--color <when>` | colorize: `auto` (TTY only, default), `always`, `never` |
| `--no-color` | alias for `--color=never` (`NO_COLOR` also disables; `--color=always` overrides) |
| `--show-bytes` | show raw instruction bytes (off by default) |
| `--source` | interleave source lines from debug info |
| `--no-pager` | do not page long output through `$PAGER` |
| `--quiet`, `-q` | bare output for pipelines (no headers/decoration) |
| `--verbose`, `-v` | extra context; `-v -v` adds debug to stderr |

**Workflow**

| Flag | Description |
| --- | --- |
| `--watch` | re-run automatically when the file changes |
| `--completions <shell>` | emit a completion script (`bash` \| `zsh` \| `fish` \| `powershell`) |
| `--help [topic]` | show help; topics: `usage formats arches examples config json` |
| `--version`, `-V` | show version, build info, arches, and formats |

## Examples

The examples below use this `demo`:

```sh
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

**List functions** — `roe demo`

```
Functions in demo
0x0000000000001000         0  _init
0x0000000000001060        34  _start
0x0000000000001090         0  deregister_tm_clones
0x00000000000010c0         0  register_tm_clones
0x0000000000001100         0  __do_global_dtors_aux
0x0000000000001140         0  frame_dummy
0x0000000000001160        60  compute
0x000000000000119c        43  main
0x00000000000011c8         0  _fini
```

**Disassemble a function** — resolved call, PLT, and string reference: see the
*objdump vs roe* listing above (`roe demo main`).

**Branch previews and labels** — `roe demo compute`

```
0x0000000000001160: test edi, edi  ; sym compute
0x0000000000001162: jle 0x1196 → [L2: mov eax, 0]
0x0000000000001164: mov ecx, 1
0x0000000000001169: mov edx, 0
0x000000000000116e: mov eax, 0
0x0000000000001173: nop
0x0000000000001175: nop word ptr cs:[rax + rax]
L1:
0x0000000000001180: lea esi, [rax + rcx]
0x0000000000001183: sub eax, edx
0x0000000000001185: test dl, 1
0x0000000000001188: cmovne eax, esi
0x000000000000118b: add edx, 1
0x000000000000118e: add ecx, 3
0x0000000000001191: cmp edi, edx
0x0000000000001193: jne 0x1180 → [L1: lea esi, [rax + rcx]]
0x0000000000001195: ret
L2:
0x0000000000001196: mov eax, 0
0x000000000000119b: ret
```

Every conditional branch shows its destination inline (`→ [L2: ...]`), and jump
targets get short labels (`L1:`, `L2:`).

**Disassemble by address** (stripped-safe) — `roe demo --addr 0x1160`

```
0x0000000000001160: test edi, edi  ; sym compute
0x0000000000001162: jle 0x1196
0x0000000000001164: mov ecx, 1
...
0x0000000000001195: ret
```

`--addr` walks from the address to a return or terminal instruction;
`--range 0x1160-0x119b` covers an inclusive range.

**Inspect any format** — `roe demo --headers`

```
Header of demo
  format:        ELF
  architecture:  x86-64
  type:          executable
  endianness:    little
  address width: 64-bit
  entry point:   0x1060
```

`roe demo --imports`

```
Imports in demo
  libraries: libc.so.6
  (unbound):
    _ITM_deregisterTMCloneTable
    _ITM_registerTMCloneTable
    __cxa_finalize
    __gmon_start__
    __libc_start_main
    printf
```

`--sections`, `--segments`, and `--exports` list the rest of the file's structure.

**Hex dump** — `roe demo --hex .rodata`

```
0x0000000000002000  01 00 02 00 63 6f 6d 70  75 74 65 28 32 30 29 20  |....compute(20) |
0x0000000000002010  3d 20 25 64 0a 00                                 |= %d..|
```

**Strings with cross-references** — `roe demo --strings`

```
0x0000000000000374  "/lib64/ld-linux-x86-64.so.2"   (no xref found)
0x0000000000002004  "compute(20) = %d\n"   used in: main @ 0x11ac
0x00000000000020b7  ";*3$\""   (no xref found)
```

**Search and analyze** — `--calls`, `--xref`, `--stats` (also `--find`, `--grep`, `--contains`)

```
$ roe demo --calls printf
Functions calling printf in demo
0x000000000000119c        43  main

$ roe demo --xref printf
References to printf (1)
0x00000000000011b8  main  call printf@plt

$ roe demo --stats
Statistics
      size  blocks  branch  depth  function
        33       3       3      0  deregister_tm_clones
        50       3       3      0  register_tm_clones
        53       4       4      1  __do_global_dtors_aux
         9       1       1      0  frame_dummy
         9       1       0      0  _fini
        34       1       1      0  _start
        43       1       2      0  main
        60       5       2      2  compute
        23       3       2      1  _init
```

**C++ (Itanium) and Rust demangling** — `roe sample_cpp.elf64 --find ::`

```
Symbols matching "::" (2)
0x000000000000112a  [symtab]  fixture::Worker::compute(int)
0x000000000000114b  [symtab]  fixture::call_worker(int)
```

**Function-level diff** — `roe v2.elf64 --diff v1.elf64`

```
Function diff
  added (1)
    added_fn
  removed (1)
    removed_fn
  changed (2)
    changed_fn
    main
  unchanged: 8
```

With a symbol argument it emits a per-function diff — `roe v2.elf64 changed_fn --diff v1.elf64`:

```
diff of changed_fn (v1.elf64 -> v2.elf64)
- lea eax, [rdi + rdi]
+ lea eax, [rdi + rdi*2]
  ret
```

**Disassemble raw bytes from stdin** — `echo '55 48 89 e5 c3' | roe --raw-bytes --arch x86_64`

```
0x0000000000000000: push rbp
0x0000000000000001: mov rbp, rsp
0x0000000000000004: ret
```

**Interleave source** (needs `-g`) — `roe demo main --source`

```
; demo.c:8  int main(void) { printf("compute(20) = %d\n", compute(20)); return 0; }
0x000000000000119c: sub rsp, 8  ; sym main
0x00000000000011a0: mov edi, 0x14
0x00000000000011a5: call compute  ; @0x1160
...
```

**Watch mode** — `roe demo main --watch` re-runs the same disassembly each time
`demo` changes on disk, so a listing stays current while you edit and rebuild.

**Across formats** — the same commands work on Mach-O and PE:

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
    EnterCriticalSection
    GetLastError
    ...
```

**Machine-readable JSON** — `roe demo main --json | jq .`

```json
{
  "instructions": [
    {
      "address": "0x119c",
      "size": 4,
      "bytes": [72, 131, 236, 8],
      "mnemonic": "sub",
      "operands": "rsp, 8",
      "label": null,
      "branch_target": null,
      "branch_preview": null,
      "symbol": {"name":"main","raw_name":"main","address":"0x119c","size":43,"exact":true,"dynamic":false},
      "reference": null,
      "string_reference": null
    },
    ...
  ]
}
```

The JSON schema is documented in [`docs/JSON_SCHEMA.md`](docs/JSON_SCHEMA.md).

## Supported formats and architectures

Disassembly is backed by [Capstone](https://www.capstone-engine.org).

| Container | Support |
| --- | --- |
| ELF (32/64-bit, little/big endian) | parsed: executables, shared objects, `.o` |
| Mach-O (x86-64 and ARM64; thin and fat) | parsed |
| PE/COFF (x86, x86-64, ARM64; `.exe` and `.dll`) | parsed |
| static archive (`.a`) | detected; extract members and inspect them individually |

| Architecture | Status |
| --- | --- |
| x86, x86-64 | fully verified |
| AArch64 (ARM64) | fully verified |
| ARM, Thumb | supported (use `--arch thumb` for Thumb code) |
| RISC-V 32/64 | supported |
| MIPS 32/64 (LE/BE) | supported |
| PowerPC 32/64 (LE/BE) | supported |

Function symbols come from ELF/Mach-O symbol tables and the PE/COFF symbol table
(falling back to the export table for stripped PEs), so `roe <file> <function>`,
`--find`, `--grep`, `--xref`, and `--stats` work by name across ELF, Mach-O, and
PE. The format-neutral `BinaryFile` interface (see
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)) keeps the disassembler, resolver,
and output code container-agnostic.

## Documentation

| Document | Contents |
| --- | --- |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | modules, the `BinaryFile` interface, data flow |
| [`docs/INTERFACES.md`](docs/INTERFACES.md) | the contract each module exposes |
| [`docs/CONFIG.md`](docs/CONFIG.md) | every config-file key |
| [`docs/JSON_SCHEMA.md`](docs/JSON_SCHEMA.md) | the JSON output schema |
| [`docs/LICENSING.md`](docs/LICENSING.md) | project and dependency licenses |
| [`SECURITY.md`](SECURITY.md) | threat model, fuzzing, reporting |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | how to contribute (DCO sign-off) |

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE). `roe` links
[Capstone](https://www.capstone-engine.org) (BSD-3-Clause); the test suite uses
Catch2 (BSL-1.0), which is not part of the released binary.
