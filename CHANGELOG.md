# Changelog

All notable changes to Recomp Studio are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `coverage` command: a non-aborting census of every recovered instruction. It
  reports total, lifted and unsupported instruction counts plus a histogram of
  unsupported instruction classes (occurrences, first site, owning function and
  the lifter's diagnostic), most frequent first. Translation stops at the first
  unsupported instruction, so a genuine application previously produced a single
  line of diagnostic; the census reports the whole gap. On a 1 MB PE32+ console
  binary it classifies 164,668 instructions in one pass (162,631 lifted, 98.76%,
  2,037 unsupported across 82 classes).
- `tests/coverage/coverage_test.py`: cross-checks the census against `analyze`
  (same recovered instruction set) and against `translate` (translation must
  succeed exactly when the census reports 100% coverage).

### Fixed

- README instruction-coverage list overstated the SSE unpack support as
  `punpck*`; only `punpckldq`/`punpckhdq`/`punpcklqdq`/`punpckhqdq` are lifted.

## [0.4.0] - 2026-10-27

### Added

- x87 floating point: the stack, control word and status word are modelled as
  guest state, with `fld`/`fild`, `fst`/`fstp`/`fist`/`fistp`, the six arithmetic
  operations and their pop forms, compares (`fcom`/`fcomp`/`fcompp`/`fucom*`/
  `ftst`), `fsqrt`/`fabs`/`fchs`/`fsin`/`fcos`/`fpatan`/`fyl2x`/`frndint`, the
  constant loads, `fxch`, `fldcw`/`fnstcw` and `fnstsw`.
- `comiss`/`comisd`/`ucomiss`/`ucomisd` (scalar FP compare into EFLAGS).
- `std`/`cld`, `loop`/`loope`/`loopne` and `jecxz`/`jrcxz`.
- `x87` differential fixture covering the stack, arithmetic, compares,
  transcendentals, control-word directed rounding, `rep movsb` under DF=1 and
  counted loops.

### Fixed

- `faddp`/`fmulp`/... wrote the result to ST(0) and then popped, discarding it;
  the pop forms now write ST(i) before popping.
- SSE `movsd`/`cmpsd` with a memory destination were decoded as the *string*
  instruction, corrupting RSI/RDI and writing 4 bytes instead of 8.

### Evidence

- The retail `igi.exe` (1,354,448 bytes, PE32) now translates with zero
  unsupported instructions across all 971 discovered functions (51,518
  instructions, 12.7% of the 406,645 decodable), and the generated project
  builds to a native arm64 binary. It does not run yet: 63/128 imports are
  implemented and startup stops at `kernel32!GetVersionExA`; user32 (30),
  avifil32 (10), winmm (9), gdi32 (3), ole32 (3), dinput (2), ddraw (2),
  dsound (1) and msvfw32 (4) have no shims.

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
