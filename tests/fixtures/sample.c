/* SPDX-License-Identifier: Apache-2.0 */
/* A small fixture exercising branches, a loop, a call, and a string literal. */
#include <stdio.h>

static int helper(int x) { return x * 3 + 1; }

int compute(int n)
{
    int acc = 0;
    for (int i = 0; i < n; i++) {
        if (i & 1) {
            acc += helper(i);
        } else {
            acc -= i;
        }
    }
    if (acc > 100) {
        acc = 100;
    }
    return acc;
}

int square(int x) { return x * x; }

int main(void)
{
    int r = compute(20);
    printf("roe sample result: %d\n", r);
    return r;
}
