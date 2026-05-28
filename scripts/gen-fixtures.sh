#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Generate the named binary fixtures used by manual verification and integration
# tests. Outputs go into tests/fixtures/ and are gitignored (never checked in).
# Cross/format toolchains are optional; missing ones are reported, not fatal.
set -u

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}/tests/fixtures"

ok() { printf '  ok    %s\n' "$1"; }
skip() { printf '  SKIP  %s (%s)\n' "$1" "$2"; }

# --- ELF (native) ---
cc -O1 -g -o branchy.elf64 branchy.c && ok branchy.elf64
cc -O1 -g -o with_strings.elf64 with_strings.c && ok with_strings.elf64
cc -O1 -g -o v1.elf64 v1.c && ok v1.elf64
cc -O1 -g -o v2.elf64 v2.c && ok v2.elf64
if command -v g++ >/dev/null 2>&1; then
    g++ -O0 -g -o cpp_demangle.elf64 cpp_symbols.cc && ok cpp_demangle.elf64
else
    skip cpp_demangle.elf64 "no g++"
fi

# --- raw shellcode (x86-64: push rbp; mov rbp,rsp; mov eax,1; ret) ---
printf '554889e5b801000000c3\n' > shellcode.hex && ok shellcode.hex

# --- Mach-O objects (clang cross-targets; objects carry imports + exports) ---
if command -v clang >/dev/null 2>&1; then
    clang --target=arm64-apple-macos11 -O1 -c -o sample.macho_arm64 macho_sample.c 2>/dev/null && ok sample.macho_arm64 || skip sample.macho_arm64 "clang arm64-apple"
    clang --target=x86_64-apple-macos11 -O1 -c -o sample.macho_x86_64 macho_sample.c 2>/dev/null && ok sample.macho_x86_64 || skip sample.macho_x86_64 "clang x86_64-apple"
else
    skip sample.macho_arm64 "no clang"
fi

# --- PE/COFF (mingw): an .exe with imports and a .dll with an export ---
if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    x86_64-w64-mingw32-gcc -O1 -o sample.pe_x64 with_strings.c 2>/dev/null && ok sample.pe_x64 || skip sample.pe_x64 "mingw64 link"
    printf '__declspec(dllexport) int roe_add(int a,int b){return a+b;}\n__declspec(dllexport) int roe_mul(int a,int b){return a*b;}\n' > /tmp/roe_dll_src.c 2>/dev/null || printf '__declspec(dllexport) int roe_add(int a,int b){return a+b;}\n' > "${repo_root}/tests/fixtures/.dllsrc.c"
    dllsrc="/tmp/roe_dll_src.c"; [ -f "$dllsrc" ] || dllsrc="${repo_root}/tests/fixtures/.dllsrc.c"
    x86_64-w64-mingw32-gcc -O1 -shared -o sample.pe_dll "$dllsrc" 2>/dev/null && ok sample.pe_dll || skip sample.pe_dll "mingw64 dll"
    rm -f "${repo_root}/tests/fixtures/.dllsrc.c"
else
    skip sample.pe_x64 "no mingw64"
fi
if command -v i686-w64-mingw32-gcc >/dev/null 2>&1; then
    i686-w64-mingw32-gcc -O1 -o sample.pe_x86 with_strings.c 2>/dev/null && ok sample.pe_x86 || skip sample.pe_x86 "mingw32 link"
else
    skip sample.pe_x86 "no mingw32"
fi

echo "fixtures generated in tests/fixtures/"
