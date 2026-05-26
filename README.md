# roe

`roe` is a disassembler fit for humans: it preserves addresses, resolves symbols and relocations, labels branch targets, previews in-function jumps inline, and keeps raw instruction bytes off by default.

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/roe --version
```

Install locally:

```sh
sudo install -m 0755 build/roe /usr/local/bin/roe
```

## Usage

```sh
roe <file>
roe <file> <symbol> [--no-color] [--show-bytes] [--json]
roe <file> --section <name> [--no-color] [--show-bytes] [--json]
roe --help
roe --version
```

Exit codes are `0` for success, `1` for usage errors, `2` for file or ELF input errors, and `3` for disassembly or resolver errors.

## Examples

Build the example binaries from source:

```sh
mkdir -p scratch/readme-demo
cc -g -O0 tests/fixtures/call_targets.c -o scratch/readme-demo/test
cc -g -O0 -fno-inline -fno-omit-frame-pointer -rdynamic tests/fixtures/branch_calls.c -o scratch/readme-demo/branch_calls
cc -g -O0 -fno-inline -fno-omit-frame-pointer -fPIC -c tests/fixtures/relocations.c -o scratch/readme-demo/relocations.o
```

List functions:

```sh
./build/roe scratch/readme-demo/test --no-color
```

```text
Functions in scratch/readme-demo/test
0x0000000000001000         0  _init
0x0000000000001050        34  _start
0x0000000000001080         0  deregister_tm_clones
0x00000000000010b0         0  register_tm_clones
0x00000000000010f0         0  __do_global_dtors_aux
0x0000000000001130         0  frame_dummy
0x0000000000001139        14  helper
0x0000000000001147        80  main
0x0000000000001198         0  _fini
```

Disassemble `main` with symbolized cross-function calls and in-function branch previews:

```sh
./build/roe scratch/readme-demo/test main --no-color
```

```text
0x0000000000001147: push rbp  ; sym main
0x0000000000001148: mov rbp, rsp
0x000000000000114b: sub rsp, 0x10
0x000000000000114f: mov dword ptr [rbp - 4], edi
0x0000000000001152: mov qword ptr [rbp - 0x10], rsi
0x0000000000001156: cmp dword ptr [rbp - 4], 0
0x000000000000115a: jns 0x1168 → [L1: mov eax, dword ptr [rbp - 4]]
0x000000000000115c: mov eax, dword ptr [rbp - 4]
0x000000000000115f: mov edi, eax
0x0000000000001161: call helper  ; @0x1139
0x0000000000001166: jmp 0x1195 → [L2: leave]
L1:
0x0000000000001168: mov eax, dword ptr [rbp - 4]
0x000000000000116b: mov edi, eax
0x000000000000116d: call helper  ; @0x1139
0x0000000000001172: mov edx, eax
0x0000000000001174: lea rax, [rip + 0xe89]
0x000000000000117b: mov esi, edx
0x000000000000117d: mov rdi, rax
0x0000000000001180: mov eax, 0
0x0000000000001185: call printf@plt  ; @0x1030
0x000000000000118a: cmp qword ptr [rbp - 0x10], 0
0x000000000000118f: sete al
0x0000000000001192: movzx eax, al
L2:
0x0000000000001195: leave
0x0000000000001196: ret
```

Show raw instruction bytes when requested:

```sh
./build/roe scratch/readme-demo/test main --show-bytes --no-color | sed -n '/call /p'
```

```text
0x0000000000001161: e8 d3 ff ff ff         call helper  ; @0x1139
0x000000000000116d: e8 c7 ff ff ff         call helper  ; @0x1139
0x0000000000001185: e8 a6 fe ff ff         call printf@plt  ; @0x1030
```

Emit JSON for tools:

```sh
./build/roe scratch/readme-demo/test main --json --no-color | sed -n '1,14p'
```

```json
{
  "instructions": [
    {
      "address": "0x1147",
      "size": 1,
      "bytes": [85],
      "mnemonic": "push",
      "operands": "rbp",
      "label": null,
      "branch_target": null,
      "branch_preview": null,
      "symbol": {"name":"main","raw_name":"main","address":"0x1147","size":80,"exact":true,"dynamic":false},
      "reference": null
    }
```

## objdump Comparison

`objdump -dr` reports relocation information on separate lines after the instruction:

```text
0000000000000000 <relocation_user>:
   0:	55                   	push   %rbp
   1:	48 89 e5             	mov    %rsp,%rbp
   4:	48 83 ec 10          	sub    $0x10,%rsp
   8:	89 7d fc             	mov    %edi,-0x4(%rbp)
   b:	8b 45 fc             	mov    -0x4(%rbp),%eax
   e:	89 c7                	mov    %eax,%edi
  10:	e8 00 00 00 00       	call   15 <relocation_user+0x15>
			11: R_X86_64_PLT32	external_function-0x4
  15:	48 8b 15 00 00 00 00 	mov    0x0(%rip),%rdx        # 1c <relocation_user+0x1c>
			18: R_X86_64_REX_GOTPCRELX	global_counter-0x4
  1c:	8b 12                	mov    (%rdx),%edx
  1e:	01 d0                	add    %edx,%eax
  20:	c9                   	leave
  21:	c3                   	ret
```

`roe` keeps addresses, hides raw bytes by default, previews the call target, and annotates relocations inline:

```text
0x0000000000000010: call 0x15 → [L1: mov rdx, qword ptr [rip]]  ; ref external_function @0x11
L1:
0x0000000000000015: mov rdx, qword ptr [rip]  ; ref global_counter @0x18
```

## Validation

Run the full local gate:

```sh
./scripts/ci.sh
```

The v0.1.0 validation suite covers normal and sanitizer builds, generated C/C++ fixtures, `/usr/bin/ls`, `/usr/bin/ssh`, `/usr/bin/python3`, and an ELF parser libFuzzer harness.
