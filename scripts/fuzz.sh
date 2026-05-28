#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build and run a roe fuzz target with libFuzzer + ASan/UBSan.
#
#   ./scripts/fuzz.sh [elf|binary|macho|pe|archive] [runs]
#
# roe parses ELF, Mach-O, and PE/COFF; static archives are detected but not
# parsed, so the archive target reports that honestly instead of pretending.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

target="${1:-elf}"
runs="${2:-1000000}"
build_dir="${ROE_FUZZ_BUILD_DIR:-build-fuzz}"

seed=""
case "${target}" in
    elf)     fuzzer="elf_parser_fuzzer";    corpus="fuzz/corpus/elf_parser" ;;
    binary)  fuzzer="binary_loader_fuzzer"; corpus="fuzz/corpus/binary_loader" ;;
    macho)   fuzzer="macho_parser_fuzzer";  corpus="fuzz/corpus/macho"; seed="tests/fixtures/sample.macho_arm64" ;;
    pe)      fuzzer="pe_parser_fuzzer";     corpus="fuzz/corpus/pe"; seed="tests/fixtures/sample.pe_x64" ;;
    archive)
        echo "roe detects static archives but does not parse them; there is no archive fuzzer." >&2
        exit 0 ;;
    *)
        echo "unknown fuzz target: ${target} (use elf, binary, macho, pe, or archive)" >&2
        exit 2 ;;
esac

if ! command -v clang++ >/dev/null 2>&1; then
    echo "clang++ is required to build libFuzzer targets" >&2
    exit 1
fi

CC="${CC:-clang}" CXX="${CXX:-clang++}" cmake -S . -B "${build_dir}" \
    -DCMAKE_BUILD_TYPE=Debug -DROE_BUILD_FUZZERS=ON -DROE_BUILD_TESTS=OFF \
    -DCMAKE_CXX_FLAGS="-fsanitize=fuzzer-no-link,address,undefined -g -O1 -fno-omit-frame-pointer" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" >/dev/null
cmake --build "${build_dir}" -j "${ROE_JOBS:-$(nproc)}" --target "${fuzzer}" >/dev/null

mkdir -p "${corpus}"
if [ -n "${seed}" ] && [ -f "${seed}" ]; then
    cp -n "${seed}" "${corpus}/seed" 2>/dev/null || true
fi
echo "Fuzzing ${fuzzer} for ${runs} runs (corpus: ${corpus})"
exec "./${build_dir}/${fuzzer}" -runs="${runs}" -max_len=1048576 "${corpus}"
