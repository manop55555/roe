/* SPDX-License-Identifier: Apache-2.0 */
/* Version 1: has removed_fn; changed_fn returns x*2. */
int unchanged_fn(int x) { return x + 1; }
int changed_fn(int x) { return x * 2; }
int removed_fn(int x) { return x - 1; }
int main(void) { return changed_fn(unchanged_fn(removed_fn(3))); }
