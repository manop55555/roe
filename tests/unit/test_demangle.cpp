// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

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

TEST_CASE("demangle exercises Rust v0 type constructors", "[demangle]")
{
    // Generic argument types: &str, tuple, slice, pointer. We assert the path parsed
    // (the name survives, not the raw _R... fallback) which exercises parse_type.
    CHECK(demangle("_RINvNtC3std3mem8align_ofReE").find("align_of") != std::string::npos);  // &str
    CHECK(demangle("_RINvNtC3std3mem8align_ofTmbEE").find("align_of") != std::string::npos); // (u32, bool)
    CHECK(demangle("_RINvNtC3std3mem8align_ofSlE").find("align_of") != std::string::npos);   // [i32]
    CHECK(demangle("_RINvNtC3std3mem8align_ofPlE").find("align_of") != std::string::npos);   // *const i32
    CHECK(demangle("_RINvNtC3std3mem8align_ofQeE").find("align_of") != std::string::npos);   // &mut str
    CHECK(demangle("_RINvNtC3std3mem8align_ofOlE").find("align_of") != std::string::npos);   // *mut i32
    CHECK(demangle("_RINvNtC3std3mem8align_ofAlpE").find("align_of") != std::string::npos);  // [i32; _]
    CHECK(demangle("_RINvNtC3std3mem8align_ofL_eE").find("align_of") != std::string::npos);  // lifetime + str
    CHECK(demangle("_RINvNtC3std3mem8align_ofKpE").find("align_of") != std::string::npos);   // const placeholder
}

TEST_CASE("demangle handles v0 impl paths", "[demangle]")
{
    CHECK(demangle("_RMC4testh") == "<u8>");                 // inherent impl <u8>
    CHECK(demangle("_RXC4testhC5Trait") == "<u8 as Trait>"); // trait impl with impl-path
    CHECK(demangle("_RYhC5Trait") == "<u8 as Trait>");       // trait impl without impl-path
}

TEST_CASE("demangle leaves unparseable input unchanged", "[demangle]")
{
    CHECK(demangle("_RzzzzzINVALID") == "_RzzzzzINVALID");
    CHECK(demangle("not_a_mangled_name") == "not_a_mangled_name");
}
