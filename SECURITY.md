# Security Policy

## Threat Model

`roe` treats object files, executables, shared libraries, archives extracted by users, and fuzz inputs as untrusted data. The primary security boundary is the parser and decode pipeline: malformed bytes must return a structured `roe::Error` instead of crashing, reading out of bounds, overflowing offsets, or exhausting memory.

The expected local attacker capability is supplying a hostile ELF file to the CLI or test/fuzz harness. `roe` does not execute target binaries, but it does parse attacker-controlled offsets, counts, string tables, symbols, relocations, and section metadata.

## Input Validation Expectations

- Validate every file range before reading from `File::image`.
- Perform offset and size arithmetic with overflow checks.
- Treat malformed ELF metadata as `ErrorCode::MalformedInput`.
- Treat unsupported but well-formed formats as `ErrorCode::UnsupportedFormat`.
- Avoid raw owning pointers and manual `new`/`delete`.
- Keep section byte iterators borrowed from `elf::File::image` and never manufacture iterators from unchecked offsets.
- Do not use exceptions for expected malformed-input control flow.
- Bound fuzz-only work so a single input cannot create unbounded helper traversal.

## Fuzzing

Build the ELF parser fuzzer with Clang:

```sh
./fuzz/generate_corpus.sh
CC=clang CXX=clang++ cmake -S . -B build-fuzz -DROE_BUILD_TESTS=OFF -DROE_BUILD_FUZZERS=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build-fuzz -j
./build-fuzz/elf_parser_fuzzer fuzz/corpus/elf_parser -runs=100000
```

The v1.0.0 release sign-off target is at least 1,000,000 libFuzzer iterations with ASan and UBSan enabled and zero crashes, leaks, or sanitizer findings:

```sh
./build-fuzz/elf_parser_fuzzer fuzz/corpus/elf_parser -runs=1000000
```

For v1.0.0, the ELF parser fuzzer completed 1,000,000 iterations with ASan and UBSan enabled and zero crashes or sanitizer findings.

## Sanitizers

Debug builds are configured to use AddressSanitizer and UndefinedBehaviorSanitizer through `roe_options`:

```sh
cmake -S . -B build-sanitize -DCMAKE_BUILD_TYPE=Debug
cmake --build build-sanitize -j
ctest --test-dir build-sanitize --output-on-failure
```

Fuzzer builds also add `-fsanitize=fuzzer,address,undefined` to fuzzer targets.

## Known Limitations

- The fuzz harnesses target the ELF, Mach-O, and PE/COFF parsers and the binary loader. Disassembly, formatting, CLI argument parsing, and resolver annotation are covered by the unit and integration suites rather than by fuzzing.
- The checked-in repository does not include large binary corpora. Corpus seeds are generated locally by `fuzz/generate_corpus.sh`.
- `roe` is a local command-line tool. It has no network listener, privilege boundary, sandbox, or automatic update channel.

## Reporting

Report crashes, sanitizer findings, or parser inputs that produce unbounded runtime or memory growth with:

- The exact command run.
- The input file or minimized reproducer.
- Compiler, sanitizer, and platform details.
- The observed crash, assertion, or sanitizer output.

Do not share sensitive proprietary binaries unless they have been minimized or cleared for disclosure.
