/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 manop55555 */
#include <stdio.h>

__attribute__((noinline)) int branchy(int value)
{
    if (value == 0) {
        return 0;
    }
    if (value < 0) {
        return -value;
    }
    return value + 1;
}

__attribute__((noinline)) int calls_external(const char* message)
{
    return puts(message);
}

int main(int argc, char** argv)
{
    const int value = branchy(argc - 1);
    if (argc > 2) {
        return calls_external(argv[1]) + value;
    }
    return value;
}

