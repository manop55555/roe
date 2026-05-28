/* SPDX-License-Identifier: Apache-2.0 */
/* Strings: two referenced by code, one referenced by nothing. */
#include <stdio.h>

__attribute__((used)) static const char unused_message[] = "unreferenced";

int error_handler(const char *what)
{
    fprintf(stderr, "Error: %s\n", what);
    return 1;
}

int main(void)
{
    printf("Hello, world!\n");
    return error_handler("disk full");
}
