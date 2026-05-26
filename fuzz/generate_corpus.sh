#!/usr/bin/env sh
set -eu

out_dir="${1:-fuzz/corpus/elf_parser}"
mkdir -p "${out_dir}"

printf 'not an elf\n' > "${out_dir}/not_elf.txt"
printf '\177ELF' > "${out_dir}/elf_magic_only.bin"

python3 - "${out_dir}" <<'PY'
from pathlib import Path
import sys

out = Path(sys.argv[1])

# ELF64 little-endian relocatable header with no section/program headers.
elf64_le_rel = bytearray(64)
elf64_le_rel[0:4] = b"\x7fELF"
elf64_le_rel[4] = 2
elf64_le_rel[5] = 1
elf64_le_rel[6] = 1
elf64_le_rel[16:18] = (1).to_bytes(2, "little")
elf64_le_rel[18:20] = (62).to_bytes(2, "little")
elf64_le_rel[20:24] = (1).to_bytes(4, "little")
elf64_le_rel[52:54] = (64).to_bytes(2, "little")
elf64_le_rel[54:56] = (56).to_bytes(2, "little")
elf64_le_rel[58:60] = (64).to_bytes(2, "little")
out.joinpath("elf64_le_relocatable_min.bin").write_bytes(elf64_le_rel)

# ELF32 big-endian executable header with no section/program headers.
elf32_be_exec = bytearray(52)
elf32_be_exec[0:4] = b"\x7fELF"
elf32_be_exec[4] = 1
elf32_be_exec[5] = 2
elf32_be_exec[6] = 1
elf32_be_exec[16:18] = (2).to_bytes(2, "big")
elf32_be_exec[18:20] = (3).to_bytes(2, "big")
elf32_be_exec[20:24] = (1).to_bytes(4, "big")
elf32_be_exec[40:42] = (52).to_bytes(2, "big")
elf32_be_exec[42:44] = (32).to_bytes(2, "big")
elf32_be_exec[46:48] = (40).to_bytes(2, "big")
out.joinpath("elf32_be_exec_min.bin").write_bytes(elf32_be_exec)
PY
