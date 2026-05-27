#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Compile a small fixture for one architecture and verify roe disassembles it.
# Committed architectures (x86_64, aarch64) fail loudly if their toolchain is
# missing; others are reported as skipped (roe still decodes them via Capstone).
#
#   ./scripts/test-arch.sh <arch>
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

arch="${1:?usage: test-arch.sh <arch>}"
roe="${ROE_BIN:-build/roe}"
if [ ! -x "${roe}" ]; then
    echo "FAIL: roe binary not found at ${roe}; run 'cmake --build build' first" >&2
    exit 1
fi

work="${ROE_BUILD_DIR:-build}/arch-fixtures"
mkdir -p "${work}"
src="${work}/arch_sample.c"
cat > "${src}" <<'EOF'
int helper(int x) { return x * 3 + 1; }
int compute(int n) {
    int acc = 0;
    for (int i = 0; i < n; i++) { if (i & 1) acc += helper(i); else acc -= i; }
    if (acc > 100) acc = 100;
    return acc;
}
EOF

flags="-c"
case "${arch}" in
    x86_64)   cc="cc" ;;
    x86)      cc="cc"; flags="-m32 -c" ;;
    aarch64)  cc="aarch64-linux-gnu-gcc" ;;
    arm|armv7) cc="arm-linux-gnueabihf-gcc" ;;
    riscv32)  cc="riscv64-linux-gnu-gcc"; flags="-march=rv32imac -mabi=ilp32 -c" ;;
    riscv64)  cc="riscv64-linux-gnu-gcc" ;;
    mips)     cc="mips-linux-gnu-gcc" ;;
    mipsel)   cc="mipsel-linux-gnu-gcc" ;;
    mips64)   cc="mips64-linux-gnuabi64-gcc" ;;
    mips64el) cc="mips64el-linux-gnuabi64-gcc" ;;
    ppc)      cc="powerpc-linux-gnu-gcc" ;;
    ppc64)    cc="powerpc64-linux-gnu-gcc" ;;
    ppc64le)  cc="powerpc64le-linux-gnu-gcc" ;;
    *) echo "unknown arch: ${arch}" >&2; exit 2 ;;
esac

committed=" x86_64 aarch64 "
if ! command -v "${cc%% *}" >/dev/null 2>&1; then
    if [[ "${committed}" == *" ${arch} "* ]]; then
        echo "FAIL: missing toolchain for committed architecture '${arch}': ${cc%% *}" >&2
        exit 1
    fi
    echo "SKIP: no '${cc%% *}' toolchain for '${arch}'; roe decodes it via Capstone but no fixture was built." >&2
    exit 0
fi

obj="${work}/arch_${arch}.o"
# shellcheck disable=SC2086
if ! "${cc}" -O1 -g ${flags} -o "${obj}" "${src}" 2>/dev/null; then
    echo "FAIL: could not compile the ${arch} fixture" >&2
    exit 1
fi

out="$("${roe}" --no-color "${obj}" compute 2>&1)" || {
    echo "FAIL: roe could not disassemble the ${arch} fixture" >&2
    echo "${out}" >&2
    exit 1
}
if ! grep -q "sym compute" <<<"${out}"; then
    echo "FAIL: ${arch} disassembly did not resolve the 'compute' symbol" >&2
    echo "${out}" >&2
    exit 1
fi
echo "PASS: ${arch} ($(grep -c '^0x' <<<"${out}") instructions, symbol resolved)"
