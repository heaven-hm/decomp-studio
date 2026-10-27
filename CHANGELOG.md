# Changelog

All notable changes to Recomp Studio are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## [0.3.0] - 2026-10-27

### Added

- 32-bit guest support: PE32/x86 executables are now decoded with `CS_MODE_32`,
  lifted with a 4-byte pointer width, executed with 32-bit address wrapping and
  the 32-bit TEB layout, and verified against a Unicorn x86-32 reference.
- Architecture-aware Win32 import ABI: a shared `runtime/win32_abi.hpp` table
  drives stdcall stack cleanup in both the runtime and the reference, so a
  32-bit stdcall callee pops its arguments exactly as on real hardware.
- Direct and indirect import calls on x86 emulate the `call`/`ret`/`ret n`
  sequence, keeping the guest stack faithful.
- `shld`/`shrd` and `lahf`/`sahf` in the x86 lifter.
- Encoded-mode-independent stack, call, return and address helpers in the
  runtime, selected by the guest pointer width.
- PE32 regression fixtures: `pe32_arith` and `pe32_abi` (cdecl, stdcall,
  fastcall, thiscall, relocation-backed dispatch, address wrapping).

### Fixed

- Function pointers stored in initialised data are recovered from base
  relocations, so indirect calls to them no longer hit unmapped addresses.
- Passing an import's 64-bit thunk address into a 32-bit IAT slot truncated it;
  the thunk base is now architecture-aware.
- x86-64 indirect calls to import thunks no longer push a return address that
  nothing pops (which drifted `rsp` and crashed).
- Unicorn's deprecated-segment-register warning is suppressed for the
  intentional FS/GS writes.

## [0.2.0] - 2026-10-27

### Added

- Real x86-64 static recompiler: PE32/PE32+ parsing, recursive-descent function
  recovery, an x86-64 → C++ lifter with exact EFLAGS semantics, a guest runtime
  with dispatch and Win32 shims, Unicorn differential verification, and an
  autonomous translate/build/verify/repair harness.
- Config-driven stubs, native overrides (HLE) and instruction patches.

### Fixed

- Parity flag polarity, IMUL/MUL zero/sign/parity flags, NEG auxiliary flag,
  undefined shift/rotate flags, LAHF/SAHF, indirect-target discovery from
  relocations, and trace comparison including import thunks.

## [0.1.0] - 2026-10-27

### Added

- Short `JB` branch decoding, x64 REX.W stack-adjustment analysis, and
  hexadecimal opcode diagnostics.
- Original Recomp Studio logo asset and README header branding.
- Reframed the project documentation around its automated, end-to-end
  recompilation workflow and verified MVP scope.
- Relicensed the project under the Apache License 2.0, including its express
  contributor patent grant.
- C++20 command-line interface with structured JSON diagnostics.
- PE32/x86 and PE32+/x64 validation, section/import reporting, and SHA-256
  executable identity.
- Entry-reachable x86/x64 instruction analysis and architecture-neutral IR
  provenance for the supported subset.
- Generated C++20 host project, native macOS ARM64 build, execution, and
  differential verification against the original instruction stream.
- Reproducible CMake/Ninja build and CTest scripts.
- Accurate fixture, TicTacToe AI, and PuTTY Plink compatibility-profile status.

### Limitations

- The release supports only a small verified instruction subset; unsupported
  operations fail closed.
- It does not yet provide general Win32, graphics, .NET, Linux, WebAssembly,
  or full-game compatibility.
