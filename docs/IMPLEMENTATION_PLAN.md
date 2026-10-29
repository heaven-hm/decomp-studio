# Decomp Studio direction and implementation plan

Decomp Studio is a general-purpose hybrid decompilation and recompilation system.
Game preservation is the initial priority: first small 2D games, then 3D games,
including Project I.G.I. Its intended input and output operating systems are
Windows, macOS and Linux; intended CPU architectures are x86, x86-64, ARM32
and ARM64. Each OS/architecture pair is a separate target requiring format,
ABI, runtime, compiler and verification work. None is implied supported merely
by appearing in this list.

## Priorities and acceptance gates

1. Preserve existing PE parsing, lifting, generated-source builds, and tests.
2. Integrate PCRecomp, Ghidra, rev.ng, Remill and LLVM through evidenced,
   license-compatible boundaries; distinguish installed providers from adapters.
3. Connect readable reconstructed functions and low-level fallback through
   explicit guest memory and ABI contracts. Build the exact delivered source.
4. Provide reusable Windows GUI, graphics, input, audio, filesystem and CRT
   compatibility without treating unimplemented behavior as success.
5. Add an independent original Windows execution oracle and deterministic input
   replay; separately report discovery, lifting, build, execution and gameplay.
6. Test small games end to end before expanding to I.G.I. and 3D workloads.
7. Extend executable formats, operating systems and guest/host architectures
   only with per-target tests and explicit unsupported diagnostics.

The following open work supersedes historical issue trackers: independent
Windows oracle and memory coverage (#11); further Remill integration (#5); an
appropriately licensed Wine-compatible runtime provider (#4); deterministic
semantic naming (#3); and the hybrid pipeline roadmap (#60). Closing historical
issues does not mean these tasks are complete.

## Historical baseline (snapshot)

The following sections describe the state measured when originally written;
branch counts, local dependencies and coverage figures are historical, not live.
The latest game results are in [the game report](../reports/real-games-2026-10-29.md).

The state of DECOMP-AGENT on `feature/decomp-agent`, what is done, what is next, and what is
known to be missing. Written from the tree, not from intention.

## Base and branch

| | |
|---|---|
| base branch | `feature/apps-running-audit` |
| **base commit** | **`ee92a6b`** |
| chosen how | ancestry, not name: it was **0 behind develop, 23 ahead** |
| working branch | `feature/decomp-agent` |
| position | **59 commits ahead of develop** |

`feature/decomp-agent` **already existed** when the directive was issued, with 11 commits of
Ghidra and PCRecomp work. Per the directive it was inspected and preserved rather than
recreated. A second worktree (`decomp-agent-codex`) has since contributed 10 more, including
the rev.ng adapter; that work was merged, not overwritten.

## The pipeline, and what is real in it

| stage | state | where |
|---|---|---|
| format / OS / CPU detection | **done** | `core/detection/` |
| PE parsing | **done** | `core/binary/pe.cpp` |
| function discovery | **done** | `core/discovery/function_discovery.cpp` |
| instruction lifting to IR | **done** | `core/semantics/x86_64_lifter.cpp` |
| IR to C++ | **done** | `core/ir/cpp_backend.cpp` |
| project generation | **done** | `core/codegen/project_generator.cpp` |
| native compilation | **done** | clang++, arm64-apple-macos11 |
| Windows API compatibility | **partial** | `runtime/recomp_runtime.cpp`, 655-entry ABI table |
| differential verification | **done** | `core/verification/differential_harness.cpp` |
| Ghidra analysis | **done**, external process | `apps/cli/ghidra_run.cpp`, `ghidra_import.cpp` |
| semantic reconciliation | **done** for addresses and conventions | `apps/cli/ghidra_reconcile.cpp` |
| rev.ng artifacts | **adapter only** | `apps/cli/revng_run.cpp` |
| PCRecomp | **scripts driven; 6 upstream HLE tests PINNED but BLOCKED** | see below |
| type recovery | **NOT STARTED** | -- |
| independent oracle | **NOT STARTED** | -- |

## Done, with the evidence

1. **The MVP pipeline runs end to end.** `ctest` passes **31 tests**; the end-to-end test
   recompiles, executes and differentially verifies **33 fixtures** (23 PE32+, 10 PE32).
2. **Ghidra is integrated** as an external process, with provenance: the record carries the
   binary's SHA-256 and distinguishes what Ghidra reported from what this project inferred.
3. **Reconciliation exists and does not merge.** `ghidra-reconcile` compares Ghidra's
   functions against this project's own discovery, reports `agreed` / `provider-only` /
   `local-only`, and exits non-zero unless the association is `verified`.
4. **The licences are established**, not assumed: PCRecomp is MIT; rev.ng is GPLv2 and must
   stay an external process; Unicorn (GPL-2.0) and radare2 (LGPL-3.0) are `required=false`
   in `tools.lock.json` as a licensing decision.
5. **The verification's limits are written down** where they cannot be missed, including the
   one that bounds everything: the reference and the candidate share a shim table.

## Next, in order

Each item is small enough to land and verify on its own.

1. **Read the provider's `calling_convention` and compare it.** The reconciler derives the
   convention from `ret N` and reports it; it does not yet read the provider's field. The rule
   is fixed: report the disagreement, do not apply it without an ABI test.
2. **`docs/IMPLEMENTATION_PLAN.md` is the last of the six required documents** -- this file.
3. **Parse the rev.ng artifact.** `revng-run` preserves it; nothing reads it. It cannot become
   a second provider until something does.
4. **Type recovery**, which is the largest gap and the one that separates what exists from
   the objective. Without it the delivered source is low-level recompilation with no recovered
   type names, which `docs/ABI_AND_TYPES.md` states plainly.
5. **An independent oracle.** Until a real Windows execution or a Frida trace is available,
   `VERIFIED` bounds the translation and not the Windows API semantics.

   **THE BLOCKER IS NOW PRECISE, and it is not the tooling.** Frida IS installed on this host
   (17.24.3, Python bindings included) -- but Frida instruments a RUNNING PROCESS, and the
   input here is a **Windows PE32**. There is no `wine` and no Windows machine, so the original
   executable **cannot be executed on this host at all**. The only thing that runs it is
   Unicorn, and Unicorn driving the shared shim table is exactly the oracle whose limits this
   section is about.

   So the oracle needs one of: a Windows host, Wine, or a machine that can execute PE32. None
   is present, and no amount of work inside this repository substitutes for one of them.

## PCRecomp: pinned correctly, and blocked by the HOST

STEP 8 asks for the upstream projects to be cloned and PINNED. PCRecomp is MIT, so it was
cloned and pinned to the exact revision the build already required:

    a85ea970f9e0640ab6546d2ca7a01fccb132973d

That pin is not a convention, it is ENFORCED: `CMakeLists.txt` refuses a different revision
and refuses a dirty checkout of the paths that matter, so the tests cannot silently run
against a different upstream.

Configuring with `-DRECOMP_PCRECOMP_SOURCE=<checkout>` activates **6 upstream HLE tests**,
taking the suite from 31 to 37. **All 6 fail on this host, and the cause is not the code:**

    dyld: Symbol not found: _HVF_clear_part_cache
      Referenced from: /opt/homebrew/Cellar/freetype/2.15.0/lib/libfreetype.6.dylib
      Expected in:     /System/Library/PrivateFrameworks/FontServices.framework/libhvf.dylib

The tests link SDL through `PkgConfig::PCRECOMP_SDL`, which pulls Homebrew's `freetype`, whose
build references a private symbol the system framework does not export. That is a Homebrew
toolchain conflict on this machine, not a defect in the pinned code or in this repository.

**So the pin is done and the tests cannot be run here.** They are left DISABLED by default
rather than enabled-and-failing: a default configuration that fails six tests is worse than one
that states why it cannot run them. The command to enable them is recorded above so that a host
without the conflict can run them in one step.

## The GUI game corpus, MEASURED

Fifteen graphical games -- 11 PE32 and 4 PE32+ -- run through `autorecomp --buildrun`. **None
completes**, and the reason each one stops is worth recording because it changed while this was
being measured:

| game | first blocker | kind |
|---|---|---|
| `gunroar` | 82 imports without shims | **runtime surface** |
| `parsec47` | 99 imports | **runtime surface** |
| `tumiki_fighters` | 95 imports | **runtime surface** |
| `snake` | 92 imports | **runtime surface** |
| `ikachan` | 21 imports | **runtime surface** |
| `cavestory` | `iretd` | lifter |
| `generally` | `cvtpd2ps` | lifter |
| `herocore` | `fbstp` | lifter |
| `noiz2sa` | `das` | lifter |
| `rrootage` | `movd` | lifter |
| `torus_trooper` | `aad` | lifter |
| `warning_forever` | `cmpltpd` | lifter |
| `cannonball` | `cvttpd2dq` | lifter |
| `opentyrian` | `cmpnless` | lifter |
| `pixeltetris` | `movntps` | lifter |

### What the first pass showed, and why the second pass is different

The first pass had **twelve of fifteen** stopping on the LIFTER, and the two commonest causes
were `jcxz` (four games) and `arpl` (three). Both are now implemented:

- **`jcxz`** is the 16-BIT form of the counter test. It was folded into the 32-bit `jecxz`
  path, which takes the branch whenever the upper bits are non-zero with CX itself zero -- a
  different program. It now masks to the low half.
- **`arpl`** adjusts a selector's requested privilege level. It was implemented for a REGISTER
  destination and **three games still stopped on it**, because `arpl [ebp-4], ax` is the
  common form and a memory destination is a read-modify-write. Both forms are now handled.
- **`fdisi8087_nop`** is the x87 no-op range. Its defined effect on a processor that has the
  features it disables is NOTHING, and refusing it stopped three games on an instruction whose
  whole purpose is to do nothing.

MEASURED: `gunroar`, `parsec47` and `tumiki_fighters` went from stopping on the lifter to
**lifting 100%**, and `herocore` went from 20,058 unsupported instructions to 2,147.

**THE CONSTRAINT MOVED.** Those three games now stop on **82, 99 and 95 missing imports** --
the Windows runtime surface -- not on the translation. That is a different problem with a
different shape: a lifter gap is a few instructions, and a GUI runtime surface is hundreds of
functions. Recording which one is binding matters more than the count of games that fail.

## Issue #67: the Windows target, measured to its actual blocker

§4 asks for Windows targets and says to distinguish **host native ISA** from **retained guest
state emulation**. Both are done here by attempting the build rather than by declaring support.

**Two real blockers were removed, and the third is recorded with its exact error.**

1. **The driver.** `clang++ -target i686-w64-mingw32` fails with
   `fatal error: 'cmath' file not found` -- clang does not know where that toolchain's headers
   are. The generated build now uses the mingw **driver** (`i686-w64-mingw32-g++`), which
   selects the same triple and knows its own sysroot. *Declaring a target and being able to
   build one are different things.*

2. **The platform layer.** The runtime included `sys/mman.h` and `unistd.h` unconditionally.
   The host-specific surface turned out to be **two includes and ONE call site**: the guest
   address space is a single anonymous mapping, `mmap` on POSIX and `VirtualAlloc(MEM_RESERVE)`
   on Windows. That is now `#ifdef _WIN32`, so the runtime compiles further than before on a
   Windows target.

3. **`__int128`, which is the actual blocker.** 32-bit mingw does not support it, and the
   runtime uses it in **10 places** -- every 64x64 multiply, divide and carry/overflow
   computation in the instruction semantics. That is the honest reason the Windows target does
   not build today, and it is a property of the SEMANTICS layer rather than of the runtime.

**The target is therefore DECLARED and the driver REACHES it, and the build stops in the
semantics layer.** Reporting "Windows supported" on the strength of a triple in a table would be
exactly the confusion the issue names.

**AND THE HONEST READING OF THE TARGET ITSELF**: even once it builds, compiling x86-32 guest
semantics with a 64-bit compiler is NOT a native x64 port. The guest state is emulated in a
`GuestContext` either way; what changes is the host pointer width. That distinction is recorded
rather than glossed, because the issue explicitly forbids relabelling guest-state C++ as native
source.

## Known gaps, recorded rather than implied

- **No type recovery.** No struct layout, no field offsets, no `static_assert` on layout.
- **No independent oracle.** The shared-shim limitation is real and unaddressed.
- **rev.ng is an adapter, not a provider.** It cannot be linked in: GPLv2.
- **Struct returns are not modelled.** A function returning a structure by hidden pointer is
  treated as returning a pointer-sized value.
- **Nondeterminism is unexplained.** `hangman` diverged in 2 of 36 identical runs; a random
  word explains the byte-count variation but not the divergence.
- **The corpus is largely unmeasured.** 157 executables; the sweeps cover a minority, and the
  counts taken before the exit-status bug was fixed need re-deriving.
- The older `feature/x86-x64-arm64-mvp` branch has divergent history; several named
  changes were separately integrated. Compare individual commits before importing any
  remaining changes.

## Metrics, kept separate

Per the directive, never merged into one percentage:

§13 requires the delivered source to be reported as TWO categories, never one, and `coverage`
now reports all three counts in both its text and JSON output:

    high-level:     bounded constant-return leaf candidates only (no general recovered signatures or types)
    low-level:      36 functions (machine-level translation)
    unresolved:     0 functions

The high-level count is now computed by a deliberately narrow recognizer. It is
not general semantic reconstruction: no recovered signatures, structures, or
types are inferred. Every function outside the exact constant-return leaf shape
remains machine-level translation. Classifying the whole binary as readable
source would be exactly the confusion the directive names.

The counts are computed, not asserted. On `clipjar.exe`: **0 high-level, 15,426 low-level,
11 unresolved** across 28 unsupported instruction classes -- so the unresolved counter fires
on a program that has unresolved functions, and a run that reports zero is reporting a
measurement rather than a constant.

| metric | how to obtain it |
|---|---|
| decoding coverage | `coverage` |
| function discovery coverage | `coverage` -- recovered function count |
| lifting coverage | `coverage` -- unsupported classes by mnemonic |
| high-level reconstruction coverage | `coverage` -- `high_level_functions` (currently only exact constant-return leaf candidates) |
| low-level fallback coverage | `coverage` -- `low_level_fallback_functions` |
| unresolved functions | `coverage` -- `unresolved_functions` |
| compilation success | the build stage's exit status |
| runtime execution success | the run stage's exit status |
| differential verification success | the `Verdict` |
| gameplay scenario coverage | **none: no game has been verified** |

## Project I.G.I. -- the first end-to-end run, MEASURED

The pipeline has now been run against `igi.exe` (1,384,448 bytes, PE32 x86, 128 imports) with
`autorecomp --buildrun`:

| stage | result |
|---|---|
| inspect | PE32 x86, 128 imports |
| recover functions | **9,475 functions, 960,403 instructions** |
| classify instruction coverage | **960,403 of 960,403 lifted, 0 unsupported** |
| check import compatibility | **95 of 128 shimmed, 33 missing** |
| translate | 9,475 functions, 128 imports |
| build native executable | **succeeded**, 45 s |
| run native executable | **exit 124** -- the 20-second ceiling, 0 bytes of output |

**What this does and does not mean.** The classifier reported all 960,403 discovered instructions as lifted, and the
result compiled to a native binary. This does not establish complete discovery or
correct instruction semantics. That is a
real result and it is the first time this pipeline has been taken to I.G.I. end to end.

It is **not** a working port. The program exits on the timeout having produced no output,
which is what a GUI game that waits for a window and input does here: there is no window
manager and no input. And **33 of its 128 imports are unimplemented**, so even reaching its
first frame is blocked on the runtime surface, not on the translation.

### The verification stage, which did NOT pass, and why

The run above was left at stage 9 and its result is now in. It **failed**, after **2088
seconds** (35 minutes):

    reference executed 200000001 instructions
    exact guest-state checkpoints matched 0/0 (0%)
    the candidate was NOT run: the reference execution did not complete
      (instruction budget reached)
    FAILED: reference_completed=no candidate_completed=no outputs_match=no

Three things are true at once here, and they are worth separating:

1. **The reference hit the instruction ceiling.** I.G.I. is a GUI game that never exits on its
   own; with no window and no input it waits forever, so the Unicorn reference runs until the
   budget stops it. The reference therefore produced **no terminal state to compare against**,
   and the harness correctly **did not run the candidate** rather than compare it with
   nothing. `candidate_completed=no` is not a translation failure -- it is the absence of an
   oracle.
2. **The verdict for this input is `INCOMPLETE`, not `VERIFIED` and not `DIVERGED`.** A
   truncated reference cannot verify anything, and the harness refuses to pretend otherwise.
   This is the correct behaviour and it is the reason truncation is checked FIRST.
3. **The reference reports its own limitation**: "the reference cannot set FS_BASE in 32-bit
   mode (unicorn 2.1.4 ignores the write); the TEB was placed at address 0 so fs: accesses
   resolve". That is a known emulator limitation carried in the result rather than hidden.

**So: the discovered I.G.I. instructions were classified as lifted, the output built natively, and the run could not be verified by this harness** --
not because the translation is wrong, but because a program that never terminates gives the
differential comparison nothing to compare. Verifying it needs a different oracle: a
deterministic input replay that drives it to a terminal state, or instrumentation of the real
executable. Neither exists.

**No game has been verified**, and the rows above are the evidence for that sentence rather
than a hedge around it.
