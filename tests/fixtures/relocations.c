/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 manop55555 */
extern int external_function(int value);

int global_counter = 7;

__attribute__((noinline)) int relocation_user(int value)
{
    return external_function(value) + global_counter;
}

__attribute__((noinline)) int local_branch(int value)
{
    if (value & 1) {
        return value + global_counter;
    }
    return value - global_counter;
}

