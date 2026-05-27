// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The roe Authors

#include "roe/resolver.hpp"

#include <catch2/catch_test_macros.hpp>

using roe::resolver::demangle;

TEST_CASE("demangle handles C++ Itanium names", "[demangle]")
{
    CHECK(demangle("_ZNSt6vectorIiSaIiEE9push_backEOi") == "std::vector<int, std::allocator<int> >::push_back(int&&)");
    CHECK(demangle("main") == "main");
    CHECK(demangle("") == "");
}

TEST_CASE("demangle strips the Rust legacy hash suffix", "[demangle]")
{
    CHECK(demangle("_ZN4core3fmt9Formatter3pad17h1234567890abcdefE") == "core::fmt::Formatter::pad");
}

TEST_CASE("demangle decodes common Rust v0 names", "[demangle]")
{
    CHECK(demangle("_RNvC9backtrace3foo") == "backtrace::foo");
    CHECK(demangle("_RNvNtCs1234_7mycrate3foo3bar") == "mycrate::foo::bar");
    CHECK(demangle("_RINvNtC3std3mem8align_ofdE") == "std::mem::align_of::<f64>");
}

TEST_CASE("demangle leaves unparseable input unchanged", "[demangle]")
{
    CHECK(demangle("_RzzzzzINVALID") == "_RzzzzzINVALID");
    CHECK(demangle("not_a_mangled_name") == "not_a_mangled_name");
}
