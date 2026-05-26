#include "../test_support.hpp"

#include "roe/core.hpp"
#include "roe/version.hpp"

#include <string>

TEST_CASE("test_core_result_value_round_trip", "[core]")
{
    auto result = roe::Result<std::string>::ok("decoded");

    REQUIRE(result.has_value());
    REQUIRE(static_cast<bool>(result));
    REQUIRE(result.value() == "decoded");
}

TEST_CASE("test_core_result_error_round_trip", "[core]")
{
    roe::Error error{roe::ErrorCode::MalformedInput, "bad magic", 4U, true};
    auto result = roe::Result<int>::err(error);

    REQUIRE(!result.has_value());
    REQUIRE(!static_cast<bool>(result));
    REQUIRE(result.error().code == roe::ErrorCode::MalformedInput);
    REQUIRE(result.error().message == "bad magic");
    REQUIRE(result.error().offset == 4U);
    REQUIRE(result.error().has_offset);
}

TEST_CASE("test_core_result_void_success_and_error", "[core]")
{
    auto success = roe::Result<void>::ok();
    auto failure = roe::Result<void>::err({roe::ErrorCode::FileIo, "open failed", 0U, false});

    REQUIRE(success.has_value());
    REQUIRE(static_cast<bool>(success));
    REQUIRE(!failure.has_value());
    REQUIRE(failure.error().code == roe::ErrorCode::FileIo);
    REQUIRE(failure.error().message == "open failed");
}

TEST_CASE("test_core_version_contract", "[core]")
{
    REQUIRE(roe::program_name == std::string("roe"));
    REQUIRE(roe::version_major == 0);
    REQUIRE(roe::version_minor == 1);
    REQUIRE(roe::version_patch == 0);
    REQUIRE(roe::version_string == std::string("0.1.0"));
}

