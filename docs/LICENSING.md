# Licensing

This document explains how `roe` is licensed, the licenses of its
dependencies, what those mean for redistribution, and the SPDX identifiers used
in the source tree.

## roe's own license

`roe` is licensed under the **Apache License, Version 2.0** (`Apache-2.0`). The
full text is in [`LICENSE`](../LICENSE), and attribution notices are in
[`NOTICE`](../NOTICE).

Apache-2.0 is a permissive, OSI-approved license. It allows free use,
modification, and redistribution in both source and binary form, including in
proprietary and commercial products, while requiring that recipients receive a
copy of the license, that modified files are marked, and that existing
copyright, patent, trademark, and attribution notices are preserved. It was
chosen because it is permissive enough to encourage adoption while providing an
explicit patent grant and a clear `NOTICE` mechanism for attribution - useful
for a tool that links third-party libraries such as Capstone.

## Dependency licenses and compatibility

| Component | Role | License | SPDX |
| --- | --- | --- | --- |
| Capstone | Linked disassembly engine | BSD 3-Clause | `BSD-3-Clause` |
| Catch2 | Test framework (build/test only) | Boost Software License 1.0 | `BSL-1.0` |

### Capstone - BSD-3-Clause

Capstone (<https://www.capstone-engine.org>) is the disassembly engine `roe`
links against. It is distributed under the 3-clause BSD license
(`Copyright (c) 2013, COSEINC. All rights reserved.`).

BSD-3-Clause is a permissive, OSI-approved license. Its only substantive
obligations are to retain the copyright notice and disclaimer in source and
binary distributions, and a non-endorsement clause. These requirements are a
subset of what Apache-2.0 already mandates, so BSD-3-Clause is **compatible
with Apache-2.0**: Capstone can be linked into and redistributed alongside
Apache-2.0 software without conflict, provided its notice is preserved.

### Catch2 - Boost Software License 1.0

Catch2 (<https://github.com/catchorg/Catch2>) is used **only to build and run
the test suite**. It is not linked into or shipped with the released `roe`
binary.

The Boost Software License 1.0 is a permissive, OSI-approved license. It is
**compatible with Apache-2.0**. Notably, BSL-1.0 does not require its license
notice to be reproduced for distributions in the form of
machine-executable object code - and because Catch2 is header-only and used
for testing only, no Catch2 code is present in distributed `roe` binaries at
all.

## Redistribution implications

When you distribute `roe`, the following must accompany the distribution:

- **Source distributions** must include [`LICENSE`](../LICENSE) (the Apache-2.0
  text) and [`NOTICE`](../NOTICE), and must preserve all existing copyright and
  attribution notices, including the per-file SPDX headers.
- **Binary distributions** must ship a copy of the Apache-2.0 license and the
  `NOTICE` file. Because the binary links Capstone, the **Capstone
  BSD-3-Clause notice must be reproduced** in the distribution; it is included
  in [`NOTICE`](../NOTICE) for that purpose. Per Apache-2.0 §4(d), the
  attribution notices in `NOTICE` must be reproduced in distributed derivative
  works.
- **Catch2** does not need to ship with binaries, since it is a build/test-only
  dependency and contributes no code to the released binary. Its notice is
  retained in `NOTICE` for completeness.

In short: ship `LICENSE` + `NOTICE` with both source and binary releases.

## SPDX identifiers in source headers

Every first-party source file carries a machine-readable SPDX header
identifying the project's own license:

```cpp
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
```

The `Apache-2.0` identifier is the canonical SPDX short form for the Apache
License, Version 2.0. The dependency identifiers referenced in this document -
`BSD-3-Clause` and `BSL-1.0` - are likewise the canonical SPDX short forms for
those licenses. SPDX identifiers from the official list at
<https://spdx.org/licenses/> are used throughout so that license scanners can
determine the license of each file and component unambiguously.
