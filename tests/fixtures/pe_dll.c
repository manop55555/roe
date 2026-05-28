/* SPDX-License-Identifier: Apache-2.0 */
/* A PE DLL fixture with exported functions. */
__declspec(dllexport) int roe_add(int a, int b) { return a + b; }
__declspec(dllexport) int roe_mul(int a, int b) { return a * b; }
