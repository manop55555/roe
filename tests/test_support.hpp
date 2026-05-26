#pragma once

#if __has_include(<catch2/catch_test_macros.hpp>)
#define ROE_TEST_USE_CATCH2 1
#include <catch2/catch_test_macros.hpp>
#else
#define ROE_TEST_USE_CATCH2 0

#include <exception>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace roe::test {

struct TestCase {
    std::string name;
    std::function<void()> body;
};

inline std::vector<TestCase>& registry()
{
    static std::vector<TestCase> tests;
    return tests;
}

class AssertionFailure : public std::runtime_error {
public:
    explicit AssertionFailure(const std::string& message) : std::runtime_error(message) {}
};

class Registrar {
public:
    Registrar(std::string name, std::function<void()> body)
    {
        registry().push_back(TestCase{std::move(name), std::move(body)});
    }
};

inline void require(bool condition, const char* expression, const char* file, int line)
{
    if (!condition) {
        throw AssertionFailure(
            std::string(file) + ":" + std::to_string(line) + ": requirement failed: " + expression);
    }
}

inline int run_all_tests()
{
    int failures = 0;
    for (const TestCase& test : registry()) {
        try {
            test.body();
            std::cout << "[pass] " << test.name << '\n';
        } catch (const std::exception& error) {
            ++failures;
            std::cerr << "[fail] " << test.name << ": " << error.what() << '\n';
        } catch (...) {
            ++failures;
            std::cerr << "[fail] " << test.name << ": unknown exception\n";
        }
    }
    return failures == 0 ? 0 : 1;
}

} // namespace roe::test

#define ROE_TEST_CONCAT_INNER(left, right) left##right
#define ROE_TEST_CONCAT(left, right) ROE_TEST_CONCAT_INNER(left, right)
#define TEST_CASE(name, tags) \
    static void ROE_TEST_CONCAT(roe_test_body_, __LINE__)(); \
    static const ::roe::test::Registrar ROE_TEST_CONCAT(roe_test_registrar_, __LINE__)( \
        (std::string(name) + " " + std::string(tags)), ROE_TEST_CONCAT(roe_test_body_, __LINE__)); \
    static void ROE_TEST_CONCAT(roe_test_body_, __LINE__)()
#define SECTION(name) if (const bool ROE_TEST_CONCAT(roe_test_section_, __LINE__) = true)
#define REQUIRE(expression) ::roe::test::require(static_cast<bool>(expression), #expression, __FILE__, __LINE__)
#define CHECK(expression) REQUIRE(expression)

int main()
{
    return ::roe::test::run_all_tests();
}
#endif

