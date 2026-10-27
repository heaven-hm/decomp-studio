# Changelog

All notable changes to Recomp Studio are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## 0.5.0

### Added

- Centralised CLI option parsing, validation and capability declarations in
  `core/cli/`. `--help` is generated from the same option table the parser
  validates against, so help and parsing cannot disagree; `capabilities` reports
  the same table as data.
- Three commands: `capabilities` (every declared value, implemented or planned,
  with what is missing for a planned one), `detect` (format, runtime,
  architecture, confidence and the evidence behind each conclusion), and
  `backends list` (source, target and reference backends).
- `--explain` on any command, printing the resolved options — unset ones showing
  their declared default — and the capability behind each choice.
- `core/detection/`, the plug-in point for input detection: PE including managed,
  ELF, Mach-O thin and universal, JVM class files, CPython bytecode and scripts.
  The language frontends are deliberately not implemented; what exists is the
  interface they will register against.

### Changed

- Version 0.5.0.
- Three rules are now enforced rather than intended: an undeclared option is an
  error and never ignored; a value outside its declared set is an error listing
  what is accepted; and a declared value this build does not implement returns
  `UNSUPPORTED` naming the option, the value and the missing capability, with exit
  code 3 distinct from the usage error's exit code 2. There is no silent fallback
  and no substitution of a different backend.
- `inspect`, `analyze`, `coverage` and `translate` all refuse an unsupported input
  through the detection layer, so the reason cannot disagree between commands.

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

- `teb32` fixture: a 32-bit guest reading its thread environment block through
  `fs:`, which is the first memory access most 32-bit Windows programs make.

- Win32 shim batch ported from HenryKun55/igi-recomp (MIT), each with the
  stdcall pop removed because this runtime pops centrally: `GetVersionExA`,
  `SetHandleCount`, `ReleaseMutex`, `FlushFileBuffers`,
  `FreeEnvironmentStringsW`, `GetEnvironmentVariableA`, `GetCPInfo`,
  `GetFileType`, `CloseHandle`, `SetStdHandle`, `CreateMutexA`,
  `GetEnvironmentStringsW`, `HeapReAlloc`, `DebugBreak`, `OutputDebugStringA`,
  `GetDriveTypeA` and `CompareFileTime`. Effect on `igi.exe`: 31 of 128 imports
  implemented becomes 42, and it now runs past CRT startup into its own code
  instead of stopping at the first Windows call.
- A Win32 handle table. Handles are opaque to the guest, but `GetFileType`,
  `CloseHandle` and the mutex and file shims have to agree about what a handle
  refers to. The three standard handles keep the values the reference also
  returns (10, 11, 12), so introducing the table changes nothing a differential
  comparison can observe.
- Real environment blocks. `GetEnvironmentStrings` returned a fixed address with
  no content, and the wide variant did not exist; both now describe the same
  host environment, double-NUL terminated, so the ANSI and wide shims agree.
- `HeapReAlloc` on the real heap, factored out of `HeapAlloc`/`HeapFree` so the
  three share one allocator.

- Function-pointer recovery from initialised data. A PE32 image with a fixed
  load address frequently carries no base relocation for an internal pointer, so
  the relocation-driven pass missed it and recursive descent could not reach it
  either — the pointer is the only reference. Data sections are now scanned for
  32-bit values that land on a routine boundary and decode as code. On `igi.exe`
  this recovers 485 further functions (971 -> 1456, 51,518 -> 83,318
  instructions) and resolves an indirect call the runtime previously refused.
  The boundary requirement matters: x86 decodes almost any byte sequence, so
  "eight instructions decode here" alone accepted a great deal of data and the
  resulting phantom functions did not lift.
- The remaining x87 forms `fisub`/`fiadd`/`fimul`/`fidiv`/`fisubr`/`fidivr`,
  `fprem`/`fprem1`, `f2xm1`, `fscale`, `fldenv`/`fnstenv`, and the no-wait
  `fstpnce`/`fstpce` stores; and the far-pointer loads `les`/`lds`/`lss`/`lfs`/
  `lgs`, which in a flat 32-bit model are ordinary 32-bit loads.
- ole32 `CoInitialize` and `CoUninitialize`, ported from igi-recomp.

- The memory forms of `bt`/`bts`/`btr`/`btc`. Only the register form was
  implemented, so `bts [mem], reg` and its siblings were unsupported. The bit
  offset is a bit-string index and can reach beyond the operand, so the address
  advances by one element per operand width.
- `xgetbv`, which reports the extended control register. This model implements
  SSE and does not implement AVX, so XCR0 advertises the SSE state only and a
  program that asks takes the SSE path — the honest answer rather than
  advertising state the recompiler cannot maintain.
- `fxsave`/`fxrstor`, the 512-byte SSE and x87 state area. Two limits are
  inherited from the x87 model rather than introduced here and are documented in
  the runtime: the registers are held as doubles so a value needing more than 53
  mantissa bits does not survive the round trip through 80-bit extended, and the
  abridged tag word is written as zero because register tags are not tracked.

  Effect: `Tetris.exe` and `snake-windows-x86_64.exe` now lift completely
  (4 and 2 unsupported instructions respectively, both to zero), so both
  translate to a native project.

- An msvcrt layer: the MSVC C runtime, implemented against the guest's own heap
  and address space. Every MSVC- or mingw-built Windows binary imports its C
  runtime, so this is not application-specific. 46 functions: the allocator
  (`malloc`/`calloc`/`realloc`/`free` on the real guest heap), the memory and
  string functions, `rand`/`srand` with a deterministic generator, the numeric
  conversions, the CRT globals (`_errno`, `_iob`, `__p__environ`, `__p__fmode`,
  `_pctype`, `__mb_cur_max`) as addresses in a reserved block, `fwrite` against
  the standard handles, and the startup calls. They are cdecl, so their ABI rows
  carry `callee_cleans_stack = false` and the caller pops, as on Windows.
- `VirtualQuery` and `VirtualProtect`. The guest address space is one flat
  committed region, so a protection change already holds and every page reports
  the same state; the fields a program inspects are filled in and the rest zeroed.

  Effect on `Tetris.exe`: 16 of 99 imports implemented becomes 48, and it runs
  from process entry through CRT startup and the C runtime into its own code.

- A guest memory watchpoint: `RECOMP_WATCH=<hex address>` reports the first write
  covering that address together with the guest instruction pointer. A corrupted
  value is otherwise very hard to trace, because the writer computed the address
  and so leaves no literal reference to it in the image.

- Function-pointer recovery from **executable** sections. The scan added earlier
  only looked at data sections, but a compiler may place a function pointer table
  inside `.text` — this program's C runtime keeps its exit table there, so
  skipping code sections missed exactly the entries the program calls on the way
  out. Tetris.exe: 412 functions becomes 495.
- The remaining legacy and x87 instructions the widened recovery reaches:
  `fptan`, `fnsave`/`frstor` (the 108-byte x87 area), `fsincos`, `fyl2xp1`,
  `xlatb`, `enter` including its display-frame copy, `aaa`, `aam`, `clc`/`stc`/
  `cmc` and `emms`. `in`, `out` and `bound` cannot work in a user-mode
  recompilation, so they fail loudly rather than doing something plausible.

  Effect: `igi.exe` lifts completely at 3,370 functions and `igi1ed.exe` at
  14,774, both with no unsupported instructions.

- Managed (.NET) image detection. Data directory 14 is the CLR runtime header,
  and a non-zero RVA there means the executable code is IL bytecode rather than
  machine code. `analyze`, `coverage` and `translate` refuse such an input with a
  diagnostic that names the cause, and `inspect` reports it. Previously
  `TicTacToe.exe` reported "coverage: complete — every recovered instruction
  lifts" from two functions and fifteen instructions, describing the CLR
  launcher stub while the program itself was never read. `inspect` also reports a
  packed image now, for the same reason.

  Corpus effect: the two .NET applications are recorded as refused rather than as
  recompilable, and four applications translate (snake, Tetris, and both IGI
  executables) against three before.

- The kernel32 console and directory surface: `Beep`,
  `SetConsoleCursorPosition`, `SetConsoleTextAttribute`, `SetConsoleCursorInfo`,
  and `FindFirstFileA`/`FindNextFileA`/`FindClose` with a real directory
  enumeration against the host filesystem and a `WIN32_FIND_DATAA` fill. The
  console calls succeed without drawing, because a recompiled port has no Windows
  console and the program's output still reaches the host's stdout.

  Effect on `Tetris.exe`: 48 of 99 imports implemented becomes 55, every kernel32
  import it needs is now present, and the remaining 44 are all C++ runtime
  (32 libstdc++, 9 msvcrt, 3 libgcc).

- The C++ runtime, and with it the first real application that runs. A GCC-built
  Windows program reaches libstdc++ through C++ member functions, so this covers
  `std::string` in both its small-buffer and heap forms, `std::ifstream` and
  `std::ofstream`, `operator<<`/`operator>>`, `operator new`/`delete`, the
  allocator and `std::ios_base::Init`, and the Universal CRT's API-set names
  (`api-ms-win-crt-*`), which carry the standard C library symbols and now
  resolve to the same implementations as `msvcrt`.
- `_initterm`, which runs the table of static initialisers the CRT is handed, so
  a C++ program's static constructors actually run. Each entry is a guest
  function and is called through the same dispatch table the guest uses.
- The last msvcrt entry points: `system`, `time`, `signal`, `strcoll`,
  `_stricoll`, `_fullpath`, `wcstombs`, `vfprintf` (including the UCRT's
  `__stdio_common_vfprintf`), `__getmainargs` and `memcmp`.

  Effect: `Tetris.exe` runs. It prints its banner, prompts for a player name,
  renders the board and the rule book, and reports `'s Score: 0   Level: 1
  High Score: 0` -- correct values rather than the addresses of its own string
  literals.

- **One shim implementation, shared by the runtime and the differential
  reference.** The reference previously modelled four Win32 imports by hand while
  the runtime implemented more than two hundred, so `verify` compared a
  translation against a program that had barely run, and an import the reference
  did not model was reported as a reference limitation rather than as a missing
  shim. The runtime is now linked into the studio, the reference maps the
  runtime's own guest address space into the emulator with `uc_mem_map_ptr`, and
  it dispatches every import through the runtime's table. There is exactly one
  implementation of each call, so the two sides cannot drift apart.
- `initialize_guest_state`, the runtime's startup (heap, environment blocks, CRT
  globals, C++ runtime) as one function that both the candidate and the reference
  call. They now begin from the same state by construction; previously the
  reference ran against an uninitialised heap and reported a divergence that said
  nothing about the translation.
- A guest output sink and an exit hook. The reference captures what the guest
  wrote instead of echoing it to the studio's stdout, and a guest `ExitProcess`
  ends the reference run instead of terminating the studio.

  Effect: the heap fixture, and every fixture, now verifies through the shared
  implementation. `verify` on `heap.exe` reports a pass where it previously
  reported that the reference could not model the heap.

- An architecture-neutral semantic representation in `core/ir/`, with the C++
  generator as its first backend. The lifter now builds statements — assign,
  store, call, branch, trap, return — and a backend decides how they are written,
  instead of the lifter writing C++ text inline. Statements that have not been
  given a structured form yet travel as `Verbatim` and are emitted unchanged, so
  the migration is incremental and cannot alter the generated code.
- A golden test, `tests/golden`, that pins the generated `guest.cpp` for all 22
  fixtures by digest. It was captured before the refactor began and the C++ output
  is byte-identical through it, which is what makes a compiler refactor
  trustworthy rather than hopeful. `coverage` also reports the migration fraction
  as a measured number (`ir statements: 1461 (71 structured, 4.86%)`).
- Segment registers read as zero, which is what the guest model has: it has no
  descriptor table. That is measured, not assumed — the reference reports `ds`,
  `es`, `ss` and `cs` all as `0x0000` in 32-bit mode for the same reason, so a
  candidate that invented the real Windows selector `0x23` would diverge on every
  instruction that stored one.

- **Guest-state differential checkpoints.** Comparing program output cannot see a
  wrong register, a wrong flag or a wrong store that never reaches the output, so
  output agreement was never sufficient evidence. The candidate and the reference
  now both record the eight general registers and the flags every 1000th executed
  guest instruction, and the verdict requires them to agree. A divergence reports
  the checkpoint index, the guest instruction, and which register or flag
  disagrees. 178 checkpoints are compared on `arith.exe`, 189 on the PE32 fixture.

- The `Trace` statement kind, and the migration of the largest shape in the
  generated code. `trace_instruction(context, 0x...); // <disassembly>` is 48.25%
  of all generated statements — 11,830 of 24,518 across the fixture corpus — and it
  comes from a single site with a fixed template. The address and the disassembly
  are separate fields, so a backend is not required to reproduce the C++ spelling.
  Structured statements go from 4.86% to **51.95%** on `arith.exe`, with the
  generated C++ still byte-identical.

- `Assign` and `StoreMemory` migrated: 20 write sites, and the IR model corrected
  to make it possible. Structured statements go from 51.95% to **86.24%** on
  `arith.exe`, with the generated C++ still byte-identical across all 22 fixtures.

  A register write is not an assignment when the register is narrower than the
  machine word: `al = x` compiles to a masked read-modify-write that preserves the
  bits above AL, and the read form of a sub-register is a cast, which is not an
  lvalue. The first attempt carried a text destination and produced code that did
  not compile. `Assign` now carries the destination register's index, width and
  high-byte offset, and the backend renders the mask — mirroring
  `register_write_statement` rather than approximating it.

- Two instruction forms that were reaching the lifter and being rejected, both
  with helpers that already existed: `unpcklps`/`unpckhps` (dword interleave) and
  `unpcklpd`/`unpckhpd` (qword interleave), which are the `punpck` operation at a
  coarser granularity; and `movq xmm, xmm`, which reads the low 64 bits of a
  vector source that the generic operand reader treated as a general register and
  threw on. A new `unpack` fixture exercises all four forms and both halves of the
  move, and verifies differentially.

- `core/detection/`, the plug-in point for input detection. It recognises PE
  (including the managed case), ELF, Mach-O thin and universal, JVM class files,
  CPython bytecode and scripts, and reports the container, the runtime, the
  architecture and the evidence each conclusion rests on. The language frontends
  themselves are deliberately NOT implemented — what exists is the interface they
  will register against, so adding one later cannot require redesigning the
  pipeline.
- A detector never guesses and never fabricates. Byte sequences that match nothing
  are reported as unrecognised rather than forced into the nearest format; a
  format that is detected but unsupported is refused with a reason naming the
  format and the missing capability. `inspect`, `analyze`, `coverage` and
  `translate` all refuse through this one path, so the reason cannot disagree
  between commands.

- Guest memory is digested at every checkpoint and compared. Registers, flags and
  output could all agree while a store lands in memory the program reads later, or
  never reads at all; a bounded digest of the stack window and the image's data
  window catches that. It is reported rather than gated, and the reason is the
  finding below.
- The image base is set by the shared startup. It was set only on the candidate
  path, so the reference digested a different range and reported a divergence that
  was an artefact of the harness.

- The executed-instruction streams can be captured from both sides and compared:
  `RECOMP_TRACE` on the candidate, `RECOMP_REF_TRACE` on the reference, each
  writing the address of every executed guest instruction. Comparing them is how a
  memory divergence is localised, and on `arith.exe` it establishes that the
  streams are **byte-for-byte identical** over 177,195 instructions — so the
  remaining difference is a store, not control flow.

- **A store the candidate never made, on x86-64 indirect calls through a
  register.** A store log on both sides (`RECOMP_STORE_LOG`,
  `RECOMP_REF_STORE_LOG`, writing `instruction address value width` per line)
  attributed the guest-memory divergence to one store rather than to one byte:
  for `call rdi` the reference logged the return address the emulated `call`
  pushed, and the candidate logged nothing. On x86-64 the thunk path passed
  `push_return = false` — deliberately, so the stack would be untouched — which
  left the candidate self-consistent but not faithful: a real `call` writes the
  return address, and skipping the write made the two sides disagree about a slot
  that later falls above the stack pointer and becomes live. The path now pushes
  and pops it, leaving the stack pointer exactly where it was while writing the
  memory hardware writes.

  Effect: `arith.exe` reports `memory: True`, and **19 of 22 fixtures now agree on
  guest memory**, up from none.

### Fixed

- Guest memory is now compared **byte by byte, with the difference classified**. A
  byte inside an aligned 8-byte slot whose two values are within one unit in the last
  place of each other is named as the documented x87 precision limit; anything else is
  a divergence. The candidate exports the windows (`RECOMP_MEMORY_WINDOWS`) because a
  digest says only *that* memory differs and classifying it needs the bytes.
  `x87.exe` now passes with a named exception rather than a silent tolerance: *"2
  byte(s) differ by at most one unit in the last place of a double; this is the
  documented x87 precision limit"*. 18 of 22 fixtures agree. `--checkpoints memory`
  still does not gate the verdict, and the reason is now narrow: two `simd_convert`
  fixtures differ by more than one ULP, and `vex` differs for the known Unicorn AVX
  defect.

- The three floating-point memory divergences are **one unit in the last place of a
  double**, which is the documented x87 precision limit and not a defect. The
  remaining difference at `x87.exe`'s checkpoint 8 is a single byte: the reference
  holds `0x40295c01a39fbd69` and the candidate `0x40295c01a39fbd68` — `12.67970000576925`
  against `12.679700005769249`, differing by `1.776e-15`, which is `2^-52 * 2^3`, the
  spacing of doubles at that magnitude. This runtime holds the x87 stack as `double`
  with a 53-bit mantissa and the reference uses 80-bit extended with 64, so a result
  needing more than 53 bits rounds differently in the last place. The documentation
  said this would happen; the investigation reached it by measurement.

  `--checkpoints memory` therefore cannot be a bit-exact gate as it stands, and the
  reason is now specific. The design that would work — compare memory exactly, and
  classify a difference as the known x87 class when every differing byte lies in an
  aligned 8-byte slot whose two values are within one unit in the last place — is
  recorded and not implemented.

- **The x87 control word was wrong on both sides of the comparison.** A guest that
  executed `FNSTCW` and compared the result exposed it: the architectural default
  after `FINIT` is `0x037f` — all exceptions masked, precision control `0b11`
  (extended), round to nearest. This runtime used `0x027f`, which selects **double**
  precision, and the Unicorn reference left its control word at `0x0000`, which is
  not a value hardware ever has. Both now start at `0x037f`. It was found by tracing
  the store that differed back to the instruction that set the register, rather than
  reading the memory it was eventually written to. With it fixed, `x87.exe`'s first
  divergence moves from checkpoint 3 to checkpoint 8, so real divergences were
  resolved and a second x87 issue remains.

- The three floating-point divergences are the **x87 status word**, and the store
  that exposed them is an ordinary one. The differing slot is written by
  `mov word ptr [rsp+0x3c], ax` — a plain 2-byte store of AX, not an x87
  instruction — so the memory difference is a symptom: AX itself differs between the
  two sides at that point, and because the divergence falls *between* checkpoints
  the register comparison never saw it. The two values are status words agreeing on
  TOP, C2 and C3 and differing in the **exception-flag field** (candidate `0x3f`,
  reference `0x00`) and in **C1**. The concrete site is `x87_round_to_float`, which
  sets `kX87PrecisionFlag` when a double does not round-trip through `float`; that
  is one of the six flags. The other five are not yet traced.

- The three floating-point memory divergences are **x87 environment state**, and the
  `WriteFile` hypothesis is refuted. Dumping the memory at the divergent checkpoint
  and diffing it localises the difference to four bytes at `ESP+332`: the reference
  holds `0x00000c00` and the candidate holds `0x027f0e7f` — `0x027f` is the x87
  control word default and the high half carries TOP=1 in the status word, which is
  what `fnstenv`/`fnsave` write. The data window matches exactly (0 of 65536 bytes).
  The store-log comparison could not see this because the write happens inside a
  shim, which is the blind spot recorded above. `x87.exe`, `simd_convert.exe` and
  `pe32_simd_convert.exe` are the three fixtures that execute `fnstenv`/`fnsave`.

- Shim writes are marked in the store log. `guest_in_shim` brackets every shim
  invocation so a store a shim performs can be told apart from a guest store, which
  matters because the reference's log is blind to the former by construction — its
  shim writes to `guest_memory` with a host `memcpy` that the emulator never
  observes. The thunk table's direct call bypassed the marker at first, leaving 335
  shim stores indistinguishable from guest stores.

  With them marked, the per-instruction comparison reports **zero** instructions
  whose written ranges differ: every guest store agrees, and the 216 differences
  reported before were all shim stores. That narrows the remaining memory divergence
  to a write a shim performs — the only class the comparison cannot see.

- The store logs are now compared **per instruction** rather than line by line, in
  `tools/compare_store_logs.py`. The reference reports a 16-byte store as two 8-byte
  writes, so a line-by-line comparison reported a divergence for every vector store;
  grouping by instruction and comparing the byte ranges each instruction wrote
  removes the question of how either side chose to chunk them. It reduced 216
  reported differences to a concrete one.
- That comparison established a limitation of the instrument itself: **the
  reference's store log cannot see writes a shim performs.** The reference dispatches
  through the same shim as the candidate, and the shim writes to `guest_memory` with
  a host `memcpy`, which Unicorn never observes as a guest access, so
  `UC_HOOK_MEM_WRITE` does not fire. A store the candidate logs and the reference
  does not is therefore not evidence of a difference — both perform it, into their
  own copy of the guest address space. The store logs are comparable for guest
  instructions and not for shim calls.

- The store log was missing every SSE store. Vector stores write memory directly
  rather than through `store_guest_memory`, so they never reached the log, and a
  16-byte `movaps` looked like a store the candidate never performed. They are
  recorded now, as one entry per register store.
- The x87 precision hypothesis for the remaining three floating-point fixtures is
  **refuted**, not confirmed. The store log records every store's width, and across
  2,204 stores on `x87.exe` the widths are `{1, 2, 4, 8}` — **there are no 10-byte
  stores at all**, so a `tbyte` round-trip through 80-bit extended cannot be the
  cause. What the logs actually disagree about is **granularity**: the candidate
  records a 16-byte vector store as one entry and Unicorn reports it as two 8-byte
  writes. Merging adjacent same-instruction writes was tried and withdrawn — it
  produced widths of 3, 5, 6, 7 and 19, which no x86 instruction can store, because
  a single instruction making two separate stores is indistinguishable from one
  store the emulator split. Comparing the logs per instruction is the normalisation
  that avoids the question, and is the next step.

- **The reference counted a `rep` instruction once per iteration.** A `rep`-prefixed
  instruction is one guest instruction that the emulator runs once per iteration,
  and Unicorn fires the code hook for each; the candidate lifts it as a single
  `string_move` and traces it once. So the reference's executed-address stream, its
  instruction count and its checkpoint indices all advanced once per byte copied —
  meaning the two sides were comparing **different points in execution** from the
  first `rep` a program ran. That is a defect in the harness, not the translation,
  and it affected every program using a string instruction. The hook now collapses
  consecutive repeats, which counts a `rep` once, as the guest instruction stream
  does; a loop that revisits an address is unaffected because it does not repeat
  consecutively. Found by comparing the streams for `x87.exe`, where the reference
  repeated `0x140001909` — `rep movsb` — while the candidate advanced. With it
  fixed those streams are identical, 9948 addresses each.

- The guest-memory digest compared **dead stack**. It covered
  `[ESP - 0x1000, ESP)`, but memory below the stack pointer is memory the program
  has moved past and cannot read again, and the two sides legitimately differ
  there. The first comparison reported a divergence at checkpoint 1 that was four
  bytes of dead stack — a return address the reference had popped and the candidate
  had overwritten — and nothing observable differed. Digesting the live stack
  `[ESP, ESP + 0x1000)` instead moved the first divergence from checkpoint 1 to
  checkpoint 175, which is what made the remaining difference small enough to
  isolate. See `reports/memory-checkpoint-finding.md`.

- The candidate and the reference did not agree on where the guest's stack begins,
  and nothing could see it. The candidate pushed a sentinel with `push_guest_stack`
  and the reference wrote one at `stack_top - pointer_width`; the two happened to
  land on the same address, but the definition lived in two places and was one
  edit away from diverging. It is one function now, used by both.

### Open, reported rather than hidden

The memory digest found a divergence the other three comparisons cannot see: at
checkpoint 1, after 1000 guest instructions at `0x1400017ab`, the stack window
differs while the registers, the flags and the program's output all agree. It is
not diagnosed. Rather than gate the verdict on a comparison that fails for an
unexplained reason -- which ends with the gate weakened or ignored, and both are
worse than a diagnostic -- `verify` reports it:

    guest-memory digest agrees: no
    checkpoint 1 after guest instruction index 1000 (0x1400017ab):
    guest memory digest 0x6bac5d86a031e69f, reference 0x5db0c91916a61c92

The next step is to bisect that window: digest the stack below the current pointer
separately from the stack above it, and separately again from the image's data.

- `0xcafebabe` is shared by Mach-O universal binaries and Java class files, and
  the Mach-O detector claimed the magic alone. A Java class file was reported as a
  "universal binary with 52 architectures" — a fabricated answer of exactly the
  kind this project forbids. The detector now validates the header it claims: a
  plausible architecture count and, for each entry, a known CPU type and a
  non-empty slice. Real universal binaries still detect, with their real count.
- `inspect --json` on an unsupported input wrote two JSON documents — the report
  and then an error object — which made the output unparseable by anything. It now
  writes exactly one and returns non-zero.

- **Verification passed with zero guest-state checkpoints compared.** The verdict
  returned true when `checkpoints_compared == 0`, on the reasoning that capture
  might have been disabled — but the harness enables capture itself before running
  either side, so zero means the capture *failed*, and the CLI printed
  `VERIFY: PASS` from a comparison that never happened. That is a verdict issued
  without the measurement it claims to rest on. A comparison of zero checkpoints
  is now a failure. Found by an independent honesty audit, not by the tests.
- `WriteFile` reported the requested length rather than what the host accepted, and
  `write_guest_output` discarded the host result entirely, so a short write — a
  full disk, a closed descriptor — was indistinguishable from success and the
  guest was told its data had been written. Both now report the accepted count.
- The golden harness passed vacuously: an empty fixture directory reported
  "checked 0 fixtures ... 0 passed, 0 failed" and exited 0, and deleting one
  fixture reported "21 passed". A harness that passes when its inputs are missing
  is worse than no harness. Every baseline entry must now have a fixture, and the
  count must match. Proven by running it against an empty directory: exit 1.

- The golden test pinned the generated code but not the input, so a rebuilt fixture
  was reported as a changed compiler — a misdiagnosis in the one test whose whole
  job is to tell those two apart, and it happened: the fixtures were rebuilt 25
  minutes after the baseline was captured and all 22 entries failed as though the
  lifter had changed. The fixture digest is pinned alongside the output now, and a
  changed input is reported as a changed input.

- The reported reference instruction count included import thunks. The counter was
  incremented before the thunk check, so `executed instructions (reference)`
  described a stream the candidate does not have — inflated by exactly the number
  of import calls, while the comment three lines below said thunks are excluded.
  On `arith.exe` the figure was 177,340 and is 177,195: 145 import calls. Found by
  a teammate reading the hook rather than the output.
- The guest-state test mutates a tracked source file, because the mutation has to
  be compiled into the candidate. An interrupted run would have left the runtime
  mutated, so it now restores from a signal handler as well as a `finally` block,
  and refuses to start if a previous run left the file dirty.

- The checkpoint reader used the 64-bit register names for a 32-bit guest.
  Unicorn returns zero for `RAX`/`RSP` in 32-bit mode rather than failing, so the
  reference appeared to report `esp = 0` — indistinguishable from a genuine state
  divergence. Found on the one PE32 fixture, which was the only one that failed.

### Fixed

- **Operand reads and writes failed silently and produced code that could not
  compile.** `mov word ptr [edi], ds` stores a segment register, and
  `operand_read_expression` returned an empty string for it, so the generated line
  was `store_guest_memory(context, addr, , 2);` — a C++ syntax error reported
  against generated code, with no mention of the instruction that caused it. This
  is the same root cause as the earlier `push cs` bug, which had been fixed
  narrowly for `push` only. Both entry points now fail closed with a diagnostic
  naming the instruction, the operand and the address, and segment registers are
  handled properly rather than being the exception. Found on `guess.exe`.

### Fixed

- Accurate input-format diagnostics. A macOS `.app`, an ELF binary or a ZIP was
  rejected with "not a DOS MZ executable", which is true and useless: it does not
  say what the file is or whether the tool could ever read it. The format is now
  named, with the architecture for Mach-O.

### Fixed

- **C++ member functions were called with the wrong arguments.** A member
  function passes `this` in ECX and its arguments on the stack from `[esp+4]`,
  but every import was modelled as cdecl or stdcall with the first argument at
  `[esp+4]`. So a member function read `this` where its first argument should
  have been and the first argument where the second should have been:
  `operator<<(int)` printed the address of the string literal written immediately
  before it. Every C++ member function import was affected. The ABI table now
  records the convention and `import_argument` reads `this` from ECX when it
  applies.
- The Universal CRT ships as API sets, one per area, so a program built against
  it did not resolve to the C library implementations that already existed under
  `msvcrt`.

### Fixed

### Fixed

### Fixed

- Alignment padding was recognised only as two literal `0x90` bytes, so a
  function preceded by a multi-byte nop (`66 90`) was rejected. That is what
  assemblers actually emit, and it hid the exit-table entries above.

### Fixed

- **A `jmp` to an import pushed a second return address.** A `jmp [iat]` thunk is
  a tail call: the caller's own `call` already pushed the return address, but the
  runtime pushed another one, shifting every argument by one slot. `memcpy` then
  read the return address as its destination and the first argument as its
  pointer-sized count, and wrote across the program's own code — which surfaced
  much later as an indirect call to a garbage address. Tail calls now go through
  `invoke_win32_import_tail`, which does not push.
- `GetProcAddress` terminated the process for a name it could not resolve. The
  real API returns NULL, and programs probe for optional symbols precisely
  because that is allowed; terminating turned a routine negative probe into a
  hard failure. A program that genuinely needs the symbol still fails, at the
  call through the null it was given, which is what Windows does too.
- The unmapped-indirect-call diagnostics reported only the target address, which
  is not actionable because the guest computed it. They now report the general
  registers as well.

### Fixed

- The import-compatibility guard only recognised `win32_`-prefixed function
  names when parsing the runtime's shim table, so it silently stopped checking
  anything a differently named shim family added — which is the drift it exists
  to catch. It now matches the table's shape rather than a naming convention, and
  immediately confirmed all 46 msvcrt rows have matching implementations.

### Fixed

### Fixed

- `push <segment register>` emitted an empty operand expression, because segment
  registers are not in the general register file, so the generated code did not
  compile. A flat address space has no selector to push, so it now fails loudly
  at run time instead of emitting nothing.
- `x87_store_environment` used `x87_status_value` before it was declared, which
  broke the generated project's build rather than the studio's.

### Fixed

- The unbound-import diagnostic did not name the import:
  `call to an unbound import thunk (ip=...)` said where but not what. The
  dispatcher already knew which import it was about to call, so it now reports
  `unimplemented Win32 import <library>!<symbol>`. Without this the on-demand
  shim loop -- run, read the first unshimmed import, port that one, repeat --
  could not work, which is the only tractable way to find out which of a
  program's imports it actually executes.

### Fixed

- **Segment bases were dropped from absolute addresses.** `mov eax, fs:[4]` was
  emitted as a read of address 4 instead of `fs_base + 4`, because the
  absolute-address fast path returned before the segment prefix was considered.
  Every 32-bit TEB read a Windows program makes went to the low page and came
  back zero — silently, since the reads were in mapped memory. Found while
  building the 32-bit TEB fixture; the same reads now resolve correctly and
  verify against the reference.
- The differential reference could not run **any** 32-bit guest. Unicorn 2.1.4
  returns `UC_ERR_OK` for `UC_X86_REG_FS_BASE` in 32-bit mode while silently
  ignoring the write (readback 0), and the harness discarded the return value,
  so `mov eax, fs:[0]` faulted on an unmapped read six instructions into a real
  2001 game executable. The write is now checked by readback, and when it cannot
  be applied the reference relocates the TEB to address 0, where `fs:[offset]`
  resolves without a base. The self-pointer still reports the canonical address
  so both sides agree. The relocation is reported in the run diagnosis rather
  than being left implicit, and the trade-off (a genuine null-page access no
  longer faults in the reference) is stated there.
- Recorded that no listed upstream project implements the SSE2 packed-integer
  family, so it could not be copied: igi-recomp's `gen.py` dispatches through
  `emit_insn`/`emit_x87` and has no occurrence of pmaddwd, psrldq, punpcklbw,
  pcmpeqb, pmuludq, pshuflw, packsswb or cvtdq2pd, and SR's
  `SRW/SR_full_llasm_instr.c` has none either.

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
