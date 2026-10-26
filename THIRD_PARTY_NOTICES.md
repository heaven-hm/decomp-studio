# Third-party notices

Recomp Studio does not vendor or redistribute third-party source code. It links
against or invokes the following components, and it was designed by studying the
listed open-source recompilation projects.

## Build and runtime dependencies

| Component | License | Use |
|-----------|---------|-----|
| [Capstone](https://github.com/capstone-engine/capstone) | BSD-3-Clause | x86-64 instruction decoding during function discovery |
| [Unicorn](https://github.com/unicorn-engine/unicorn) | GPL-2.0 | Reference execution for differential verification (optional, `RECOMP_ENABLE_UNICORN`) |
| [LLVM/Clang](https://github.com/llvm/llvm-project) | Apache-2.0 with LLVM exception | Host code generation for generated C++ |
| [CMake](https://cmake.org) / [Ninja](https://github.com/ninja-build/ninja) | BSD-3-Clause / Apache-2.0 | Build system |
| [mingw-w64](https://github.com/mingw-w64/mingw-w64) | Public domain / Zope / BSD variants | Compiling the test fixtures into real Windows PE executables |

Unicorn is GPL-2.0. It is used only by the verification backend. Building without
`-DRECOMP_ENABLE_UNICORN=ON` (or without Unicorn present) produces a core
recompiler and CLI that link only Capstone. Distributing a binary that links
Unicorn requires compliance with the GPL-2.0.

## Design references (studied, not copied)

These projects informed the architecture (config-driven recompilation, one C
function per guest function, a flat guest address space, a guest dispatch table
for indirect control flow, and a runtime-provided compatibility layer):

| Project | License | Influence |
|---------|---------|-----------|
| [N64Recomp](https://github.com/N64Recomp/N64Recomp) | MIT (c) 2024 Wiseguy | Config-driven recompilation, per-function output, stubs/patches/hooks, single flat translation model |
| [igi-recomp](https://github.com/HenryKun55/igi-recomp) | MIT (c) 2026 HenryKun55 | x86-to-C translation model, backward flag liveness, jump-table switches, high-level emulation and native function replacement |
| [Zelda 64: Recompiled](https://github.com/Zelda64Recomp/Zelda64Recomp) | MIT | Runtime integration pattern for recompiled output |

No code from these projects is included in this repository. Where a technique is
adopted it has been reimplemented.

## Fixtures

The test fixtures under `tests/fixtures/apps` are original programs written for
this project and compiled locally with mingw-w64. No commercial game binaries,
copyrighted assets, or proprietary SDKs are included or downloaded.
