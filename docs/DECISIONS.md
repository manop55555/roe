# roe Decisions

- Use C++17 because it satisfies the project requirement and keeps dependency assumptions modest.
- Use `Result<T, Error>` style APIs because malformed binaries are expected inputs, not exceptional control flow.
- Keep ELF parsing, disassembly, resolution, formatting, and CLI as separate modules to make ownership and fuzzing clear.
- Store file bytes in `elf::File::image` so section byte views are valid without memory mapping lifetime hazards.
- Make formatting own labels and branch previews because labels are output policy, not disassembly facts.
- Represent arm64 in public APIs but allow an `UnsupportedFormat` result until x86-64 is complete.
- Keep the initial CMake file source-glob based with placeholder targets so agents can add `.cpp` files without editing build plumbing first.
- Fuzz the ELF parser from owned byte vectors first because every CLI workflow depends on this trust boundary.
- Generate fuzz corpus seeds locally instead of checking in binary fixtures to keep the repository reviewable and lightweight.
- Ignore debug and unwind relocation sections during instruction annotation because relocatable objects use section-relative offsets that otherwise collide with `.text`.
- Render branch previews inline with `\u2192` because the CLI contract requires preview text, not multi-line arrow diagrams.
