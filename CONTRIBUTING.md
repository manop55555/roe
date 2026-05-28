# Contributing to roe

Thanks for your interest in improving `roe`, a disassembler fit for humans.
This guide covers how to build and test the project, the commit conventions we
use, and the legal sign-off required for every contribution.

## Building and testing

`roe` is a C++17 project built with CMake. A typical development cycle is:

```sh
cmake -B build && cmake --build build
ctest --test-dir build --output-on-failure
```

Capstone is required to build the tool; Catch2 is used for the test suite only.
For sanitizer, fuzzing, and full-gate instructions, see [`SECURITY.md`](SECURITY.md)
and `./scripts/ci.sh`. Please make sure the build is clean and the tests pass
before opening a pull request.

## Commit style

We use [Conventional Commits](https://www.conventionalcommits.org). Each commit
message starts with a type prefix describing the change:

- `feat:` — a new feature.
- `fix:` — a bug fix.
- `docs:` — documentation-only changes.
- `test:` — adding or updating tests.
- `refactor:` — a code change that neither fixes a bug nor adds a feature.

Example:

```text
feat: preview in-function jump targets inline
```

Keep the subject line short and in the imperative mood. Add a body when the
change needs explanation.

## Licensing of contributions

`roe` is licensed under the [Apache License, Version 2.0](LICENSE). By
contributing, you agree that your contributions are submitted under the same
Apache-2.0 license, with no additional terms or conditions. New source files
should carry the standard SPDX header:

```cpp
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
```

## Developer Certificate of Origin (DCO)

All contributions must be made under the
[Developer Certificate of Origin (DCO)](https://developercertificate.org/),
version 1.1. The DCO is a lightweight way for contributors to certify that they
wrote, or otherwise have the right to submit, the code they are contributing.

You certify your agreement to the DCO by adding a `Signed-off-by` line to each
commit. The easiest way to do this is to pass the `-s` (or `--signoff`) flag
when committing:

```sh
git commit -s -m "fix: bound relocation table reads"
```

This appends a line to the commit message that matches your Git author identity:

```text
Signed-off-by: Your Name <you@example.com>
```

The name and email in the sign-off must match your commit author information.
Commits without a valid `Signed-off-by` line cannot be merged.

The full text of the DCO follows.

```text
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

## Code of Conduct

This project adopts the [Contributor Covenant](https://www.contributor-covenant.org)
as its Code of Conduct. By participating, you are expected to uphold its
standards of respectful, harassment-free collaboration. Please report
unacceptable behavior to the project maintainers.
