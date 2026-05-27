// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The roe Authors
#pragma once

/**
 * @file core.hpp
 * @brief Shared error and Result types for roe public APIs.
 */

#include <cassert>
#include <cstdint>
#include <string>
#include <utility>
#include <variant>

namespace roe {

/**
 * @brief Stable error categories returned by public module APIs.
 */
enum class ErrorCode : std::uint8_t {
    Ok = 0,
    Usage,
    FileIo,
    MalformedInput,
    UnsupportedFormat,
    NotFound,
    Disassembly,
    Resolution,
    Formatting,
    Internal
};

/**
 * @brief Structured error returned through Result.
 */
struct Error {
    ErrorCode code{ErrorCode::Ok};
    std::string message;
    std::uint64_t offset{0};
    bool has_offset{false};
};

/**
 * @brief Result type for APIs that either produce a value or an Error.
 *
 * This type is intended for expected failures such as invalid arguments,
 * malformed ELF input, unsupported architectures, and missing symbols.
 */
template <typename T>
class Result {
public:
    static Result ok(T value) { return Result(std::move(value)); }
    static Result err(Error error) { return Result(std::move(error)); }

    [[nodiscard]] bool has_value() const noexcept { return std::holds_alternative<T>(storage_); }
    explicit operator bool() const noexcept { return has_value(); }

    T& value() & {
        assert(has_value());
        return std::get<T>(storage_);
    }

    const T& value() const& {
        assert(has_value());
        return std::get<T>(storage_);
    }

    T&& value() && {
        assert(has_value());
        return std::move(std::get<T>(storage_));
    }

    const Error& error() const& {
        assert(!has_value());
        return std::get<Error>(storage_);
    }

    Error&& error() && {
        assert(!has_value());
        return std::move(std::get<Error>(storage_));
    }

private:
    explicit Result(T value) : storage_(std::move(value)) {}
    explicit Result(Error error) : storage_(std::move(error)) {}

    std::variant<T, Error> storage_;
};

/**
 * @brief Result specialization for APIs that only need success or Error.
 */
template <>
class Result<void> {
public:
    static Result ok() { return Result(); }
    static Result err(Error error) { return Result(std::move(error)); }

    [[nodiscard]] bool has_value() const noexcept { return !error_.has_value; }
    explicit operator bool() const noexcept { return has_value(); }

    void value() const { assert(has_value()); }

    const Error& error() const& {
        assert(!has_value());
        return error_.error;
    }

    Error&& error() && {
        assert(!has_value());
        return std::move(error_.error);
    }

private:
    struct StoredError {
        Error error;
        bool has_value{false};
    };

    Result() = default;
    explicit Result(Error error) : error_{std::move(error), true} {}

    StoredError error_;
};

} // namespace roe
