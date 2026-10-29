# Implementation plan

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
| PCRecomp | **scripts driven; runtime self-tests** | pinned sources |
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
- **19 commits on `feature/x86-x64-arm64-mvp` remain unintegrated**, including jump-table
  discovery, `InitCommonControls`, `FormatMessageA` and the SSE fixes. This is the largest
  single body of unmerged work and it is a deliberate merge decision, not an oversight.

## Metrics, kept separate

Per the directive, never merged into one percentage:

| metric | how to obtain it |
|---|---|
| decoding coverage | `coverage` |
| function discovery coverage | `coverage` -- recovered function count |
| lifting coverage | `coverage` -- unsupported classes by mnemonic |
| high-level reconstruction coverage | **not measurable yet: no type recovery** |
| low-level fallback coverage | all recovered functions are low-level fallbacks today |
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

**What this does and does not mean.** The machine code is recovered and lifted completely --
every one of 960,403 instructions -- and the result compiles to a native binary. That is a
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

**So: I.G.I. lifts completely, builds natively, and CANNOT BE VERIFIED BY THIS HARNESS** --
not because the translation is wrong, but because a program that never terminates gives the
differential comparison nothing to compare. Verifying it needs a different oracle: a
deterministic input replay that drives it to a terminal state, or instrumentation of the real
executable. Neither exists.

**No game has been verified**, and the rows above are the evidence for that sentence rather
than a hedge around it.
