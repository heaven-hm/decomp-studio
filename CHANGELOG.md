# Changelog

All notable changes to Recomp Studio are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `bswap` (32- and 64-bit, zero-extending), `cld`/`std` (the direction flag is
  now set, and the runtime's string-operation helpers already honoured it), and
  the `repz`/`repnz` prefix spellings — including the `repz ret` padding idiom
  MSVC emits, which alone blocked the first three real applications.
- `byteops` fixture: BSWAP at both widths plus a backward and a forward
  `rep movsb` copy, so a direction flag that is ignored or stuck set prints
  `gfedcba` instead of `abcdefg`. Verified byte-identical against the Unicorn
  reference; a mutation that makes `cld` a no-op fails verification.
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

- `btr` was silently wrong: it emitted `original & mask` instead of
  `original & ~mask`, so instead of clearing the tested bit it kept *only* that
  bit and destroyed every other one. A `btr` of bit 5 in `0xffffffffffffffff`
  produced `32` rather than `-33`. The existing fixtures never covered the
  register form, and the error was found while diagnosing the eight `btr` sites
  in a real binary. Now covered by the `bitops` fixture.
- README instruction-coverage list overstated the SSE unpack support as
  `punpck*`; only `punpckldq`/`punpckhdq`/`punpcklqdq`/`punpckhqdq` are lifted.
- `coverage` classified unsupported instructions by the raw Capstone mnemonic
  while the lift diagnostic names the prefix-stripped one, so an unsupported
  `lock bts` would have been reported under a class name its own reason
  contradicted.

### Verified against real applications

Instruction coverage of the genuine Windows binaries in the mission set, after
this change (unsupported instructions / distinct classes):

| Application | Format | Before | After |
| --- | --- | --- | --- |
| `imgview64.exe` | PE32+ | 10 / 3 | **0 / 0 (100%)** |
| `Tetris.exe` | PE32 | 14 / 7 | 11 / 6 |
| `plink.exe` | PE32+ | 2,037 / 82 | 1,927 / 81 |
| `igi.exe` (final target) | PE32 | 540 / 33 | 536 / 31 |

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
