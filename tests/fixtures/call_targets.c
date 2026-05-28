/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 manop55555 */
#include <stdio.h>

int helper(int x)
{
    return x * 2;
}

int main(int argc, char** argv)
{
    if (argc < 0) {
        return helper(argc);
    }
    printf("hello: %d\n", helper(argc));
    return argv == 0;
}
