# Verification

What this project's verification does, what it does NOT do, and how each gate was itself
tested. The second section is the one that matters: a gate nobody has tried to defeat is a
gate nobody knows works.

## The claim a verdict makes

`Verdict` (`core/verification/differential_harness.hpp`) is a single decision function with
six outcomes: `VERIFIED`, `DIVERGED`, `REFERENCE_UNSUPPORTED`, `CANDIDATE_UNSUPPORTED`,
`INCOMPLETE`, `NOT_RUN`. `verified()` is `verdict() == VERIFIED` -- there is no second path
that can report success.

**Truncation is checked FIRST.** A run cut off by the instruction ceiling returns
`INCOMPLETE`, and no comparison result can override it. This ordering was wrong twice during
development and both times produced a false success: once a budget-limited run was reported
`CANDIDATE_UNSUPPORTED`, and once a truncated reference was reported `NOT_RUN`. The order is
the fix, and the reason it is checked first is that every other outcome is a statement about
a run that finished.

## What is compared

| field | meaning when true |
|---|---|
| `outputs_match` | the two sides' stdout is byte-identical |
| `checkpoints_matched` / `checkpoints_total` | guest registers, flags, x87 control and status, `mxcsr`, at each 1000-instruction checkpoint |
| `dirty_pages_compared` | heap pages whose per-page digest agrees, **compared at the same checkpoint on both sides** |
| `exit_codes_match` | the two sides returned the same status |
| `control_registers_match` | control registers agree |

Every one of these defaults to **false** and is set true only where a comparison actually
ran. They defaulted true once, and a run with zero checkpoints printed "guest-memory digest
agrees: yes" -- an agreement between two things that were never read.

## The limit, stated where it cannot be missed

**The reference and the candidate call the SAME shim table.** A Win32 shim wrong in the same
way on both sides agrees with itself. So:

> `VERIFIED` bounds the TRANSLATION -- that the machine code was lifted faithfully. It does
> NOT bound the Windows API semantics. A program can be VERIFIED and still behave
> differently from a real Windows machine.

The directive names this as a limitation to address. Addressing it needs an **independent
oracle**: execution of the original on real Windows, or Frida instrumentation of it. Neither
is implemented. Until one is, this section is the honest scope of every verification claim
the project makes.

## Gates, and the test that tries to defeat each

Each gate has a mutation test that injects a specific defect and asserts the gate NOTICES.
Without one, a gate that never fires is indistinguishable from a gate that works.

| gate | how it was tested |
|---|---|
| guest-state comparison | `tests/verification/guest_state_test.py` patches the **generated project's** runtime copy to XOR one flag bit, and asserts the change is detected, the output is UNCHANGED, and the diagnosis names the checkpoint |
| heap-page comparison | `tests/verification/heap_corruption_test.py` injects a one-byte heap difference and asserts `memory_match` is false **while `outputs_match` is still true** -- proving the corruption never reached stdout and the heap comparison is what caught it |
| exit-status comparison | `tests/fixtures/apps/nonzero_exit.c` returns 3 on purpose |
| truncation | the instruction budget is exercised and the verdict asserted to be `INCOMPLETE` |
| unsupported imports | `tests/fixtures/apps/unsupported_import.c` imports a symbol the runtime genuinely lacks, and the run must FAIL naming it |

**A test may not edit tracked source to prove something.** `guest_state_test.py` used to write
its mutation into `runtime/recomp_runtime.cpp` -- the source tree -- which made `ctest -j`
unsafe and left the tree poisoned after a hard kill. It now patches the generated project's
copy. The fixture whose whole purpose is a missing import had to be re-pointed when
`MessageBoxA` was implemented: **a negative fixture's symbol moves**, and a fixture that
passes for the right reason has stopped being a test.

## The bugs these gates found in THEMSELVES

Recorded because they are the evidence that the gates work, and because each one is a way a
verification system lies:

1. **The reference's exit status was recorded but never copied** into the result the caller
   reads, so it was permanently 0 and the comparison always saw a disagreement. It reported
   `dominosasolver` as a failed port for two rounds. **A fixture that exercised the new gate
   is what caught it.**
2. **The exit status was never compared at all** before that: `candidate_completed` was
   `exit_code == 0`, which marks every program that legitimately exits non-zero as broken.
3. **The run stage had the same bug in a second place**, so `autorecomp` printed
   `AUTORECOMP FAILED` and `verified yes` in the same output.
4. **The heap comparison compared two different points in time** -- the candidate's
   checkpoint-0 digest against the reference's FINAL memory.
5. **It compared decimal against hex**, so every page "differed" even when the diagnosis
   printed the same value on both sides.
6. **A discovery heuristic passed every fixture and invented 1,851 functions** on a real
   application. Every later discovery change is now measured against its own baseline first.

## Nondeterminism, which is not yet explained

- `hangman_x64` picks a random word; its output length varies 345-357 bytes between runs, so
  a recorded byte count is ONE SAMPLE.
- **2 of 36 verification runs of the same byte-identical `hangman` binaries DIVERGED** with
  identical output. The other four apps diverged 0 times in 24 runs.

  **REPRODUCED AND NARROWED.** Twelve further runs of the same binary against the same
  generated project gave **11 VERIFIED and 1 DIVERGED** -- about 8%, consistent with the
  2-in-36 first observed. The one divergence carried a specific diagnosis:

      checkpoint 1: the guest instruction stream differs at 0x4010...

  So the divergence is in the **INSTRUCTION STREAM** and not in memory or output: the two
  sides execute a different sequence from some point, which is a control-flow difference
  rather than a stored-value difference. Fifteen further runs did not reproduce it, which
  fixes the rate as low and makes it expensive to chase by repetition.

  **This matters more than its rarity suggests.** It means a single `VERIFIED` result is not
  proof that a re-run would agree, and the honest way to state any verification result from
  this harness is "verified on this run". A defect that appears once in twelve runs will
  survive any check that runs once.

  **CAUSE FOUND AND FIXED: THE HOST CLOCK.** The runtime read the wall clock with
  `std::time(nullptr)` and `clock_gettime`. The candidate is a SUBPROCESS and the reference
  runs in the harness process, so the two called the host clock at different instants -- and a
  program that seeds its RNG from the time, `srand(time(NULL))`, which is the idiom, received
  a **different seed on each side** whenever the two runs straddled a second boundary. The
  guest then chose a different word, took a different branch, and the two instruction streams
  diverged. That is exactly the diagnosis: *"the guest instruction stream differs"*.

  It was rare because most runs land inside one second and some do not.

  **The clock is an INPUT to the guest, and a differential comparison is only meaningful if
  both sides receive the same input.** `guest_fixed_time()` now returns a fixed instant
  (overridable with `RECOMP_FIXED_TIME`), and every guest-visible clock read goes through it,
  including the monotonic tick count.

  **MEASURED: 0 divergences in 42 consecutive runs**, where the rate before was about 8%. At
  8%, 42 clean runs would occur about 3% of the time.

  This also corrected a TEST whose assertion was the bug: `runtime_time_test` checked that the
  guest's time lay between two HOST readings -- which is the coupling that caused the
  divergence. It now checks what matters: that the guest's clock is DETERMINISTIC, plausible,
  and that `GetLocalTime` agrees with the runtime's own `_time64` rather than with the host.
- `testtmp`-based fixtures are affected by machine load: a corpus sweep under memory pressure
  (load average 73) produced 13 spurious SIGKILL results that all produced real verdicts when
  re-run, and three applications that PASSED were first recorded as failures.

None of these is hidden behind a tolerance. A divergence is reported as a divergence.

## What the metrics mean, separately

Per the directive, these are never merged into one percentage:

| metric | source |
|---|---|
| decoding coverage | `coverage` -- every recovered instruction decodes |
| lifting coverage | `coverage` -- instructions that lift, and the unsupported CLASSES by mnemonic |
| function discovery | recovered function count |
| compilation success | the build stage's exit status |
| runtime execution | the run stage's exit status |
| differential verification | the `Verdict` |
| ported applications | `APPLICATIONS.md` and `CORPUS.md`, each row with its own evidence |

A program at 100% lift with a missing import is not 100% supported, and the reports say so
in those words.
