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

- `imports` command: reports the program's operating-system surface — which
  imported functions have a shim and which are missing — grouped by library,
  worst first, with every missing symbol listed. Instruction coverage says
  whether the code can be lifted; this says whether the calls it makes exist. On
  `igi.exe` it reports 128 imports, 31 implemented (24.22%), 97 missing, with
  the gap concentrated in `kernel32` (33), `user32` (30), `avifil32` (10) and
  `winmm` (9).
- `tests/compat/imports_test.py`: pins the report against `inspect` for the
  import count, and parses both `runtime/win32_abi.hpp` and
  `runtime/recomp_runtime.cpp` to require the declared shim set and the
  implemented shim set to agree exactly, so the "implemented" count cannot claim
  an import works when the runtime would terminate on it.

- `autorecomp` command: runs the whole pipeline in order — detect the host
  target, inspect, recover functions, classify coverage, check import
  compatibility, translate, build, and with `--buildrun` run and verify — with a
  live spinner, per-step timings, a log file per run and an optional `--repair`
  loop. `--target` is detected from the host when omitted; `--buildrun` reuses
  the existing build and run steps; the animation is suppressed when stdout is
  not a terminal, under `--json`, or when `NO_COLOR` is set.
- `tests/autorecomp/autorecomp_test.py`: 36 checks covering the verified path,
  build-only mode, the log file, agreement with `analyze`, and the honesty rule
  below.

- VEX (AVX) encodings of instructions the lifter already implemented: a
  two-operand VEX instruction reuses the SSE handling for the same operands, and
  a three-operand one becomes `dst = src1` followed by that operation, so the
  upper half of a scalar destination comes from src1 as the SDM requires.
  `cvtsi2ss` and `cvttss2si` were missing and are added. Effect on real
  applications: Pixeltetris.exe 556 -> 279 unsupported, legacy-notepad-x64.exe
  177 -> 123, clipjar.exe 1635 -> 1326.
- 256-bit `ymm` state: the guest vector register file is now 32 bytes per
  register (the low 16 remain the xmm view) with `load_guest_vector_256` /
  `store_guest_vector_256` helpers, and the lifter emits 32-byte moves when a
  `ymm` operand is involved. AVX widened the architectural registers, so a
  128-bit-only file could not represent a guest that uses `ymm` at all, and
  `vmovdqu ymm0, [rdx]` was the first blocker in both Pixeltetris.exe and
  legacy-notepad-x64.exe. Effect: Pixeltetris.exe 279 -> 210 unsupported,
  legacy-notepad-x64.exe 123 -> 72.
- `tests/vex/vex_test.py`: checks the VEX fixture by value against the SDM, and
  asserts the fixture stays out of the differential suite.

- A real guest heap. `HeapFree` was a no-op and `HeapAlloc` only bumped a
  pointer, so a guest that allocates and frees in a loop consumed the region
  until allocations returned null — which is what loading a level does. It is now
  a boundary-tag allocator with splitting and coalescing, and it returns null
  only when the region is genuinely exhausted, as the real API does.
- `tests/heap/heap_test.py` and the `heap` fixture: 200 MB through a 128 MB
  region, which the old allocator failed around round 128.

- The SSE2 packed-integer family: element-wise add/subtract (wrapping and
  saturating, signed and unsigned), packed compares, multiplies, logical not-and,
  immediate and variable shifts, whole-register byte shifts, unpack, pack, byte
  and half-word shuffles, multiply-add, sum-of-absolute-differences, and
  PMOVMSKB. The runtime generates a register and a memory form of each helper
  from one macro so the two cannot drift. Effect on real applications
  (unsupported instructions): plink.exe 1818 -> 279, powder.exe 9809 -> 1919,
  rg.exe 2188 -> 725, bat.exe 2150 -> 594, clipjar.exe 1301 -> 449,
  legacy-notepad-x64.exe 72 -> 26, Pixeltetris.exe 210 -> 125.
- `cvtdq2pd`, `pushfd`/`popfd` (and the 64- and 16-bit spellings),
  `vzeroupper`/`vzeroall`, and the three-operand `pshuflw`/`pshufhw` form, which
  was silently unsupported because the operand guard assumed two operands.
- The `packed` fixture: 47 operations checked byte-identically against the
  Unicorn reference, including both shift forms, all three saturation widths and
  the pack/unpack lane layout.

- Packed-image detection. A UPX-packed executable keeps its real code in a
  section that has no bytes in the file, so recovering functions decodes
  whatever the packer left behind: `imgview64.exe` was reported at 100%
  instruction coverage and 30,299 "lifted" instructions, 19,836 of which were
  the two-byte sequence `00 00` decoded as `add [eax], al` from zero padding.
  `translate` and `coverage` now refuse a packed image and name the reason
  instead of producing a confident, wrong answer.
- `tests/apps/real_apps_test.py`: runs every genuine Windows application in the
  corpus through the whole pipeline and prints PASS/FAIL per application, so the
  real corpus is visible in the suite. It fails on a regression against
  `tests/apps/baseline.json` — a rising unsupported-instruction count, a stage
  that used to succeed failing, or a verification that used to pass no longer
  passing — and reports improvements rather than failing them. It skips with a
  clear message when `RECOMP_APPS_DIR` is unset, because the corpus is not
  redistributable. Current state: 17 applications, 3 translate, 0 verify.
- `cwd`, `tzcnt`, `fcomi`/`fcompi`/`fucomi`/`fucompi`, `fcmovcc` and `fxam`.
  Together these took `igi1ed.exe` from 1374 unsupported instructions in 11
  classes to 0, so both Project I.G.I. executables now lift completely.

### Fixed

- Five helpers the lifter emits for a memory operand did not exist:
  `vector_add_dwords_memory`, `vector_subtract_dwords_memory`,
  `vector_compare_equal_dwords_memory`, `vector_multiply_add_words_memory` and
  `vector_sum_absolute_differences_memory`. `paddd xmm1, [mem]` and four others
  produced generated C++ that would not compile, while `coverage` reported them
  as lifted — 43 instances in otherwise-clean functions across two corpus
  binaries. Found by an independent audit that compiled a probe referencing
  exactly the emitted symbols; the same probe now passes. The three dword
  helpers became macro-generated pairs and the two special forms gained explicit
  memory twins, so the register and memory forms cannot drift again.

### Fixed

- Variable-count shifts used the wrong count. The SDM takes ONE count — the low
  64 bits of the source operand — and applies it to every element; the helpers
  were shifting each element by its corresponding source element, so a source
  whose low 64 bits were 2 shifted element 0 by 2, element 1 by 0, element 3 by
  3. Found by independent audit verified against real x86 silicon under
  Rosetta 2 (1192 mismatches on random vectors, 1120 of them `psraw`/`psrad`).
  The register and memory forms now read the count once and delegate to the
  immediate helpers.
- `psubsb`/`psubsw` and `paddsb`/`paddsw` had saturation holes at `a == 0`:
  `0x00 - 0x80` wrapped to `0x80` instead of clamping to `0x7f`. They now clamp
  on the exact integer difference rather than on sign guards.
- `pmuludq` produced 32-bit results. It is not a uniform element-wise multiply:
  it multiplies the low dwords of elements 0 and 2 and writes two 64-bit
  results. Routing it through the generic element-wise helper truncated the
  product back to 32 bits and lost the high half. Found by the new fixture —
  which failed verification on exactly this line — before the independent audit
  that was asked to look for it reported.
- Recorded that no listed upstream project implements this instruction family,
  so it could not be copied: igi-recomp's `gen.py` dispatches through
  `emit_insn`/`emit_x87` and has no occurrence of pmaddwd, psrldq, punpcklbw,
  pcmpeqb, pmuludq, pshuflw, packsswb or cvtdq2pd; SR's
  `SRW/SR_full_llasm_instr.c` has none either. The only hits in SR are udis86's
  decoder tables, not semantics. Wine has no x86 lifter at all and N64Recomp
  lifts MIPS.

### Fixed

- Two vector-move defects, both found by independent audit of the VEX work
  (`reports/gap-census.md`) and both reachable in lifted code:
  * a register-to-register move narrower than 16 bytes was emitted as a 16-byte
    copy, so `movsd xmm2, xmm0` clobbered the upper half that SSE requires it to
    preserve (`movss` likewise). 68 instructions across 8 binaries.
  * the three-operand VEX src1 copy hardcoded 16 bytes, so a `ymm` destination
    kept half of src1 stale. 107 instructions, mostly `vpand ymm, ymm, ymm`.
  The `vecmove` fixture pins the merge semantics and is differentially verified;
  mutation-tested, the old code prints `movsd_hi=22`/`movss_lane3=0` and fails.
- The differential reference no longer fabricates a result. It models four
  imports and returned 0 for everything else, which made a comparison "pass"
  against a program whose reference run was meaningless. It now stops and
  reports `reference does not model <library>!<symbol>`, so verification fails
  closed like everything else. This also corrects the documentation: the
  executed-address trace is a post-failure diagnostic, not a pass/fail gate, and
  the reference does not have "the same shim semantics as the runtime" — it has
  4 of 63. Sharing one shim implementation is the real fix and is tracked.

### Fixed

- `autorecomp` reported `AUTORECOMP COMPLETE` and exited 0 for a program that
  built but then failed to run and failed verification, because only thrown
  exceptions were recorded while the run and verify steps report failure by
  returning a status. `igi.exe`-class targets would have been declared ported on
  that basis. Success now requires the requested pipeline to finish *and*, with
  `--buildrun`, the program to verify; a failed run is reported as
  `AUTORECOMP FAILED` with a non-zero exit. Verification also still runs after a
  failed run, since it produces the real diagnosis.
- Recorded that Unicorn 2.1.4 cannot adjudicate VEX/AVX, so VEX correctness is
  established against the SDM and QEMU's `ops_sse.h` (`SSE_HELPER_S`) rather than
  differentially. Unicorn issue #1074 ("incorrect emulation of most VEX
  instructions", naming `vpxor`) and PR #1658 ("AVX is not supported", "YMM isn't
  supported in qemu upstream at all") are the upstream statements; both were
  reproduced here, and in both cases the reference disagrees with the SDM and
  with QEMU's own source, not with this project's translation.
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

## [0.3.1] - 2026-10-27

### Added

- `CVTDQ2PS` (packed signed dword → packed single precision) for XMM and 128-bit
  memory operands, honouring the MXCSR rounding-control mode (nearest-even,
  toward −∞, toward +∞, toward zero) and setting the precision flag on inexact
  conversion.
- MXCSR is now modelled as guest state: `LDMXCSR` loads it from memory and
  `STMXCSR` stores the real value instead of a constant `0x1f80`.
- Differential fixtures `simd_convert` (PE32+) and `pe32_simd_convert` (PE32)
  covering normal, negative, 2^24-boundary and int32-extreme inputs under all
  four rounding modes, the memory operand form, and MXCSR round-tripping.

### Fixed

- The unspecified rounding of `CVTDQ2PS` was previously unimplemented, blocking
  any program that uses it; the rounding bracket is computed from both adjacent
  floats so directed rounding is correct at the precision boundary.

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
