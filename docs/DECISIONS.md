# roe Decisions

- Use C++17 because it satisfies the project requirement and keeps dependency assumptions modest.
- Use `Result<T, Error>` style APIs because malformed binaries are expected inputs, not exceptional control flow.
- Keep ELF parsing, disassembly, resolution, formatting, and CLI as separate modules to make ownership and fuzzing clear.
- Store file bytes in `elf::File::image` so section byte views are valid without memory mapping lifetime hazards.
- Make formatting own labels and branch previews because labels are output policy, not disassembly facts.
- Represent each architecture uniformly in the public APIs and return `UnsupportedFormat` for inputs roe recognizes but does not decode.
- Keep the CMake build source-glob based so new `.cpp` files are picked up without editing build plumbing.
- Fuzz the ELF parser from owned byte vectors first because every CLI workflow depends on this trust boundary.
- Generate fuzz corpus seeds locally instead of checking in binary fixtures to keep the repository reviewable and lightweight.
- Ignore debug and unwind relocation sections during instruction annotation because relocatable objects use section-relative offsets that otherwise collide with `.text`.
- Render branch previews inline with `\u2192` because the CLI contract requires preview text, not multi-line arrow diagrams.
- Hide raw instruction bytes by default because the CLI is optimized for human scanning; `--show-bytes` restores them.
- Synthesize x86-64 PLT symbols from `.rela.plt` order and `.plt` entry layout so direct calls can render as `name@plt`.
- Add `binary::BinaryFile` above parser-specific models so v1 workflows do not encode ELF-only assumptions.
- Keep the ELF-specific APIs alongside the `BinaryFile` adapters so existing call sites and the format-neutral interface coexist.
- Return owned section bytes in the v1 binary model because fat binaries and archive members make borrowed iterator lifetimes fragile.
- Detect formats by magic bytes only because extension-based detection is not reliable for object files and archives.
- Treat fat Mach-O slices and archive members as `binary::Object` entries so object selection is uniform.
- Put Capstone architecture selection behind `disasm::options_for` so parsers only emit normalized architecture enums.
- Keep debug information optional and non-fatal because `--source` must fall back gracefully without breaking disassembly.
- Define xrefs, stats, and search as feature-layer data models so text and JSON formatters share one analysis result.
- Put watch mode behind `roe::watcher` because inotify, kqueue, and ReadDirectoryChangesW require platform-specific implementations.
- Install man pages, headers, legal files, and completion artifacts from CMake so packaging shares one release layout.

## v1.0.0 scope and implementation

- Parse ELF, Mach-O, and PE/COFF directly; static archives are detected by magic, and their members are extracted for individual inspection. The format-neutral `BinaryFile` interface keeps every parser behind one model.
- Treat x86-64 and AArch64 as the production architectures (real cross-compiled fixtures, every feature, including ARM64 ADRP+ADD string references); the other Capstone arches are wired and unit-tested against known encodings but are best-effort.
- Resolve RISC-V branch targets by adding the instruction address, because this Capstone build reports RISC-V branch immediates as PC-relative offsets while other ISAs report absolute targets.
- Enable Capstone's compressed-instruction mode (RVC) for RISC-V so real `-Os`/`-O1` code, which is full of compressed instructions, decodes completely.
- Recover string references on x86 from RIP-relative/absolute memory operands and on AArch64 by pairing ADRP with the following ADD/LDR; other ISAs materialize addresses across more instructions and are left unannotated rather than guessed.
- Filter compiler-internal local labels (`.L*`) and ARM mapping symbols (`$a/$t/$d`) from listings and relocation annotations so relocatable `.o` output stays readable.
- Implement a self-contained Rust v0 demangler for the common path/identifier/type grammar with backreferences and a step/depth budget; it falls back to the raw symbol on unmodeled constructs (function-pointer and `dyn` types, some const generics) rather than risk wrong output.
- Select ARM vs Thumb with `--arch thumb` rather than auto-detecting `$a/$t` mapping symbols, which keeps the disassembler stateless.
- Accept that the inotify/poll watch loop and the interactive pager path are exercised by integration use rather than unit tests; their change-detection and decision logic are factored out and unit-tested, which is why those files show lower line coverage.
