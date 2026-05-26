#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

build_dir="${ROE_BUILD_DIR:-build}"
sanitize_dir="${ROE_SANITIZE_BUILD_DIR:-build-sanitize}"

cmake -S . -B "${build_dir}" -DCMAKE_BUILD_TYPE=Release
cmake --build "${build_dir}" -j "${ROE_JOBS:-$(nproc)}"
ctest --test-dir "${build_dir}" --output-on-failure

cmake -S . -B "${sanitize_dir}" -DCMAKE_BUILD_TYPE=Debug
cmake --build "${sanitize_dir}" -j "${ROE_JOBS:-$(nproc)}"
ctest --test-dir "${sanitize_dir}" --output-on-failure

if command -v rg >/dev/null 2>&1; then
    if rg -n --hidden -g '!build*/**' -g '!.*cache*/**' -g '!.git/**' -e '[T]ODO|[F]IXME|[X]XX' \
        CMakeLists.txt include src tests scripts docs fuzz; then
        echo "forbidden marker check failed" >&2
        exit 1
    fi
else
    if grep -RInE '[T]ODO|[F]IXME|[X]XX' CMakeLists.txt include src tests scripts docs fuzz \
        --exclude-dir=.git --exclude-dir='build*' --exclude-dir=CMakeFiles \
        --exclude-dir="${build_dir}" --exclude-dir="${sanitize_dir}"; then
        echo "forbidden marker check failed" >&2
        exit 1
    fi
fi

if command -v gcovr >/dev/null 2>&1; then
    coverage_dir="${ROE_COVERAGE_BUILD_DIR:-build-coverage}"
    if cmake -S . -B "${coverage_dir}" -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_CXX_FLAGS="--coverage" -DCMAKE_EXE_LINKER_FLAGS="--coverage" >/dev/null &&
        cmake --build "${coverage_dir}" -j "${ROE_JOBS:-$(nproc)}" >/dev/null &&
        ctest --test-dir "${coverage_dir}" --output-on-failure >/dev/null; then
        gcovr -r . --filter 'src/' --exclude 'tests/' --txt
    else
        echo "coverage build skipped: coverage instrumentation failed" >&2
    fi
else
    echo "coverage skipped: gcovr not found" >&2
fi
