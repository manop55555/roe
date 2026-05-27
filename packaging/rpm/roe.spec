Name:           roe
Version:        1.0.0
Release:        1%{?dist}
Summary:        A disassembler fit for humans

License:        Apache-2.0
URL:            https://github.com/USER/roe
Source0:        https://github.com/USER/roe/archive/refs/tags/v%{version}.tar.gz#/%{name}-%{version}.tar.gz

BuildRequires:  cmake
BuildRequires:  gcc-c++
BuildRequires:  capstone-devel
BuildRequires:  pkgconfig

Requires:       capstone

%description
roe is a command-line disassembler that prioritizes readable output. It
preserves addresses, resolves symbols and relocations, labels branch
targets, previews in-function jumps inline, and keeps raw instruction
bytes off by default. It can list functions, disassemble a single symbol
or section, annotate cross-function calls and relocations, and emit JSON
for downstream tooling. roe is built on the Capstone disassembly engine.

%prep
%autosetup -n %{name}-%{version}

%build
%cmake -DCMAKE_BUILD_TYPE=Release -DROE_BUILD_TESTS=OFF
%cmake_build

%install
%cmake_install

%files
%license LICENSE
%doc NOTICE
%{_bindir}/roe
%{_mandir}/man1/roe.1*

%changelog
* Tue May 26 2026 Manopakorn <manopakorn.sec@gmail.com> - 1.0.0-1
- Initial release.
