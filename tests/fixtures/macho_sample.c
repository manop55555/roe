/* SPDX-License-Identifier: Apache-2.0 */
/* A Mach-O object fixture with an import (external_func) and exports. */
extern int external_func(int);

int my_helper(int x) { return x * 3 + 1; }

int my_export(int x) { return external_func(my_helper(x)) + 1; }
