# roe

`roe` is a readable ELF disassembly tool for Linux. It lists functions, disassembles one symbol or a whole section, preserves addresses, labels branch targets, previews jumps inline, and annotates relocations with human-readable names.

## Build

Requirements:

- CMake 3.16 or newer
- C++17 compiler
- Capstone development package discoverable by `pkg-config`

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/roe --version
```

For a local install into `/usr/local/bin` today:

```sh
sudo install -m 0755 build/roe /usr/local/bin/roe
```

Package-manager installs are planned after v0.1.0.

## Usage

```sh
roe <file>
roe <file> <symbol> [--no-color] [--json]
roe <file> --section <name> [--no-color] [--json]
roe --help
roe --version
```

Exit codes are `0` for success, `1` for usage errors, `2` for file or ELF input errors, and `3` for disassembly or resolver errors.

## Examples

Build the example fixtures from source:

```sh
mkdir -p scratch/readme-demo
cc -g -O0 -fno-inline -fno-omit-frame-pointer -rdynamic tests/fixtures/branch_calls.c -o scratch/readme-demo/branch_calls
cc -g -O0 -fno-inline -fno-omit-frame-pointer -fPIC -c tests/fixtures/relocations.c -o scratch/readme-demo/relocations.o
```

List functions:

```sh
./build/roe scratch/readme-demo/branch_calls --no-color
```

Sample output:

```text
Functions in scratch/readme-demo/branch_calls
0x0000000000001000         0  _init
0x0000000000001050        34  _start [dyn]
0x0000000000001139        41  branchy [dyn]
0x0000000000001162        26  calls_external [dyn]
```

Disassemble one function with inline branch previews:

```sh
./build/roe scratch/readme-demo/branch_calls branchy --no-color
```

Sample output:

```text
0x0000000000001144: 75 07                  jne 0x114d → [L1: cmp dword ptr [rbp - 4], 0]
0x0000000000001146: b8 00 00 00 00         mov eax, 0
0x000000000000114b: eb 13                  jmp 0x1160 → [L3: pop rbp]
L1:
0x000000000000114d: 83 7d fc 00            cmp dword ptr [rbp - 4], 0
```

Emit JSON for tools:

```sh
./build/roe scratch/readme-demo/branch_calls branchy --json --no-color
```

Sample output starts with:

```json
{
  "instructions": [
    {
      "address": "0x1139",
      "size": 1,
      "bytes": [85],
      "mnemonic": "push",
      "operands": "rbp"
    }
  ]
}
```

Disassemble a whole section:

```sh
./build/roe scratch/readme-demo/branch_calls --section .text --no-color
```

## objdump Comparison

`objdump -dr` reports relocation information on a separate line after the instruction:

```text
  10: e8 00 00 00 00        call   15 <relocation_user+0x15>
      11: R_X86_64_PLT32    external_function-0x4
  15: 48 8b 15 00 00 00 00  mov    0x0(%rip),%rdx
      18: R_X86_64_REX_GOTPCRELX global_counter-0x4
```

`roe` keeps the instruction address and attaches the resolved reference inline:

```text
0x0000000000000010: e8 00 00 00 00         call 0x15 → [L1: mov rdx, qword ptr [rip]]  ; ref external_function @0x11
L1:
0x0000000000000015: 48 8b 15 00 00 00 00   mov rdx, qword ptr [rip]  ; ref global_counter @0x18
```

## Validation

Run the full local gate:

```sh
./scripts/ci.sh
```

The v0.1.0 validation suite covers normal and sanitizer builds, generated C/C++ fixtures, `/usr/bin/ls`, `/usr/bin/ssh`, `/usr/bin/python3`, and an ELF parser libFuzzer harness. The release gate measured 9 passing test executables, 81.32% `src/` line coverage, 1,000,000 fuzz iterations, and a 281,304-byte stripped binary.
