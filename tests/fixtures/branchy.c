/* SPDX-License-Identifier: Apache-2.0 */
/* A branch-heavy fixture: a helper, a loop with conditionals, and a call. */
#include <stdio.h>

int helper(int x)
{
    if (x < 0) {
        return -x;
    }
    return x * 2;
}

int branchy(int n)
{
    int acc = 0;
    for (int i = 0; i < n; i++) {
        if (i % 3 == 0) {
            acc += helper(i);
        } else if (i % 3 == 1) {
            acc -= i;
        } else {
            acc ^= i;
        }
    }
    if (acc > 1000) {
        acc = 1000;
    }
    return acc;
}

int main(void)
{
    printf("branchy(50) = %d\n", branchy(50));
    return 0;
}
