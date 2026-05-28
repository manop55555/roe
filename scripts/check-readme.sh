#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Verify the README's worked example reproduces against the built roe binary.
# Exact addresses depend on the local toolchain, so this checks the salient,
# documented behaviors (resolved calls, the string reference, labels/previews,
# xref and stats output) rather than a byte-for-byte diff.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

roe="${ROE_BIN:-build/roe}"
if [ ! -x "${roe}" ]; then
    echo "FAIL: roe binary not found at ${roe}; run 'cmake --build build' first" >&2
    exit 1
fi

work="${ROE_BUILD_DIR:-build}/readme-check"
mkdir -p "${work}"
demo_src="${work}/demo.c"
demo="${work}/demo"
cat > "${demo_src}" <<'EOF'
#include <stdio.h>
static int helper(int x) { return x * 3 + 1; }
int compute(int n) {
    int acc = 0;
    for (int i = 0; i < n; i++) { if (i & 1) acc += helper(i); else acc -= i; }
    return acc;
}
int main(void) { printf("compute(20) = %d\n", compute(20)); return 0; }
EOF
cc -O1 -g -o "${demo}" "${demo_src}"

fail=0
expect() { # <description> <text-that-must-appear> <command...>
    local desc="$1" needle="$2"; shift 2
    local out; out="$("$@" 2>&1)"
    if grep -qF -- "${needle}" <<<"${out}"; then
        echo "ok: ${desc}"
    else
        echo "FAIL: ${desc} - expected to find: ${needle}" >&2
        echo "${out}" >&2
        fail=1
    fi
}

expect "main resolves the call to compute"   "call compute"                "${roe}" --no-color "${demo}" main
expect "main resolves the PLT call to printf" "call printf@plt"            "${roe}" --no-color "${demo}" main
expect "main annotates the string reference" 'compute(20) = %d'            "${roe}" --no-color "${demo}" main
expect "compute previews a branch target"    "→ ["                         "${roe}" --no-color "${demo}" compute
expect "compute labels a jump target"        "L1:"                         "${roe}" --no-color "${demo}" compute
expect "stats reports the compute function"  "compute"                     "${roe}" --no-color "${demo}" --stats
expect "xref finds the printf call site"     "call printf@plt"             "${roe}" --no-color "${demo}" --xref printf
expect "version names the project"           "disassembler fit for humans" "${roe}" --version

if [ "${fail}" -ne 0 ]; then
    echo "README check failed." >&2
    exit 1
fi
echo "README examples reproduce."
