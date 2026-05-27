#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build with coverage instrumentation, run the test suite, and report src/ line
# coverage. Fails if coverage drops below the threshold (default 80%).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

build_dir="${ROE_COVERAGE_BUILD_DIR:-build-coverage}"
threshold="${ROE_COVERAGE_MIN:-80}"

if ! command -v gcovr >/dev/null 2>&1; then
    echo "gcovr is required for coverage reporting (apt-get install gcovr)" >&2
    exit 1
fi

cmake -S . -B "${build_dir}" -DCMAKE_BUILD_TYPE=Debug -DROE_BUILD_TESTS=ON \
    -DCMAKE_CXX_FLAGS="--coverage -O0" -DCMAKE_EXE_LINKER_FLAGS="--coverage" >/dev/null
find "${build_dir}" -name '*.gcda' -delete 2>/dev/null || true
cmake --build "${build_dir}" -j "${ROE_JOBS:-$(nproc)}" >/dev/null
ctest --test-dir "${build_dir}" --output-on-failure

gcovr --root . --filter 'src/' --print-summary --fail-under-line "${threshold}" "${build_dir}"
