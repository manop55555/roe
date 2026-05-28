// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
//
// End-to-end coverage for the two features that were previously exercised only
// by hand: --watch (re-run on file change) and the pager (spawned on a TTY,
// bypassed when piped or with --no-pager). Both drive the real roe binary as a
// subprocess so a regression in the CLI wiring is caught, not just the library.

#include "../test_support.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

#include <unistd.h>

using roe_test::CommandResult;
using roe_test::contains;
using roe_test::repo_root_from;
using roe_test::roe_executable;
using roe_test::run_command;
using roe_test::shell_quote;

namespace {

std::filesystem::path make_temp_dir(const std::string& tag)
{
    const std::filesystem::path base = std::filesystem::temp_directory_path();
    for (int attempt = 0; attempt < 100; ++attempt) {
        std::filesystem::path candidate =
            base / ("roe-" + tag + "-" + std::to_string(static_cast<long long>(getpid())) + "-" +
                    std::to_string(attempt));
        std::error_code error;
        if (std::filesystem::create_directory(candidate, error)) {
            return candidate;
        }
    }
    return {};
}

// Compile tests/fixtures/sample.c (defines `compute`) into `out`. Returns true on success.
bool compile_sample(const std::filesystem::path& out)
{
    const std::filesystem::path root = repo_root_from(__FILE__);
    if (root.empty()) {
        return false;
    }
    const std::filesystem::path src = root / "tests" / "fixtures" / "sample.c";
    const CommandResult build =
        run_command("cc -O0 -g " + shell_quote(src.string()) + " -o " + shell_quote(out.string()));
    return build.exit_code == 0 && std::filesystem::exists(out);
}

int find_int_after(const std::string& text, const std::string& key)
{
    const std::size_t position = text.find(key);
    if (position == std::string::npos) {
        return -1;
    }
    return std::atoi(text.c_str() + position + key.size());
}

} // namespace

TEST_CASE("watch mode re-runs disassembly when the watched file changes", "[watch][integration]")
{
    const std::filesystem::path roe = roe_executable();
    if (roe.empty()) {
        SUCCEED("roe binary not found next to the test; skipping watch integration test");
        return;
    }

    const std::filesystem::path dir = make_temp_dir("watch");
    REQUIRE_FALSE(dir.empty());
    const std::filesystem::path bin = dir / "watch_sample";
    if (!compile_sample(bin)) {
        std::error_code cleanup;
        std::filesystem::remove_all(dir, cleanup);
        SUCCEED("could not compile sample fixture (no C compiler); skipping");
        return;
    }
    const std::filesystem::path out = dir / "watch.out";

    // Background roe in watch mode, poll for the run_immediately initial run, modify
    // the file, poll for the re-run, then stop the process (TERM, then KILL fallback).
    const std::string quoted_out = shell_quote(out.string());
    const std::string script = std::string("set +e\n") + shell_quote(roe.string()) + " " +
        shell_quote(bin.string()) + " compute --no-color --watch > " + quoted_out + " 2>&1 &\n" +
        "pid=$!\n"
        "for i in $(seq 1 60); do grep -q 'sym compute' " + quoted_out + " && break; sleep 0.1; done\n"
        "before=$(grep -c 'sym compute' " + quoted_out + ")\n"
        "touch " + shell_quote(bin.string()) + "\n"
        "for i in $(seq 1 60); do [ \"$(grep -c 'sym compute' " + quoted_out +
        ")\" -gt \"$before\" ] && break; sleep 0.1; done\n"
        "after=$(grep -c 'sym compute' " + quoted_out + ")\n"
        "kill -TERM $pid 2>/dev/null; sleep 0.5; kill -KILL $pid 2>/dev/null; wait $pid 2>/dev/null\n"
        "echo \"BEFORE=$before AFTER=$after\"\n";

    const CommandResult result = run_command("sh -c " + shell_quote(script));

    std::error_code cleanup;
    std::filesystem::remove_all(dir, cleanup);

    INFO("watch harness output:\n" << result.output);
    const int before = find_int_after(result.output, "BEFORE=");
    const int after = find_int_after(result.output, "AFTER=");
    CHECK(before >= 1);       // run_immediately produced the initial disassembly
    CHECK(after > before);    // the touch triggered at least one re-run
}

TEST_CASE("pager is spawned on a TTY and bypassed when piped or with --no-pager", "[pager][integration]")
{
    const std::filesystem::path roe = roe_executable();
    if (roe.empty()) {
        SUCCEED("roe binary not found next to the test; skipping pager integration test");
        return;
    }

    const std::filesystem::path dir = make_temp_dir("pager");
    REQUIRE_FALSE(dir.empty());
    const std::filesystem::path bin = dir / "pager_sample";
    if (!compile_sample(bin)) {
        std::error_code cleanup;
        std::filesystem::remove_all(dir, cleanup);
        SUCCEED("could not compile sample fixture (no C compiler); skipping");
        return;
    }

    // A pager that tags every line it receives, so its presence is observable.
    const std::filesystem::path marker = dir / "mark_pager.sh";
    {
        std::ofstream out(marker);
        out << "#!/bin/sh\nsed 's/^/PAGED:/'\n";
    }
    std::filesystem::permissions(marker, std::filesystem::perms::owner_all, std::filesystem::perm_options::add);

    const std::string pager_env = "PAGER=" + shell_quote(marker.string()) + " ";
    const std::string all = shell_quote(roe.string()) + " " + shell_quote(bin.string()) + " --all";

    // Piped (stdout is the capture pipe, not a TTY): must NOT page — pipe safety.
    const CommandResult piped = run_command(pager_env + all);
    CHECK(piped.exit_code == 0);
    CHECK(contains(piped.output, "0x"));
    CHECK_FALSE(contains(piped.output, "PAGED:"));

    const bool have_script = run_command("command -v script").exit_code == 0;
    if (have_script) {
        // Under script(1) stdout is a pseudo-TTY and the output (161 lines) exceeds a
        // screen, so the pager must run.
        const CommandResult tty = run_command(
            pager_env + "script -qc " + shell_quote(all) + " /dev/null");
        INFO("tty pager output head:\n" << tty.output.substr(0, 200));
        CHECK(contains(tty.output, "PAGED:"));

        // Same TTY conditions but --no-pager: the pager must be bypassed.
        const CommandResult bypass = run_command(
            pager_env + "script -qc " + shell_quote(all + " --no-pager") + " /dev/null");
        CHECK_FALSE(contains(bypass.output, "PAGED:"));
    } else {
        WARN("script(1) not available; skipped the TTY pager-spawn assertions");
    }

    std::error_code cleanup;
    std::filesystem::remove_all(dir, cleanup);
}
