/* SPDX-License-Identifier: Apache-2.0 */
/* Version 2: removed_fn gone, added_fn new; changed_fn returns x*3. */
int unchanged_fn(int x) { return x + 1; }
int changed_fn(int x) { return x * 3; }
int added_fn(int x) { return x + 100; }
int main(void) { return changed_fn(unchanged_fn(added_fn(3))); }
