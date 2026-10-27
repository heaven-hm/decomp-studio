# Guest-state checkpoint divergences across the fixture corpus

**Author:** state-divergence-analyst (teammate)
**Date:** 2026-10-27
**Branch:** `feature/x86-x64-arm64-mvp` (HEAD `87a8aa1`, working tree dirty — see *Reproducibility*)
**Scope:** every fixture in `tests/fixtures/apps/bin/*.exe`, run through
`translate` → `build` → `verify --json`.

---

## 1. Headline

**The stated premise does not reproduce.**

- `fixture_recompile_end_to_end` **PASSES** on this tree: `1/1 Test #4 ... Passed 53.01 sec`
  (standalone) and `Passed 70.82 sec` inside the full suite (`100% tests passed, 0 tests failed
  out of 13`). The full suite at the time of that run also passed 13/13.
- **No fixture passes the stdout comparison while disagreeing on guest state.** Every one of the
  19 fixtures that `recompile_test.py` requires reports `outputs_match: true` *and*
  `state_match: true`, with a non-zero `checkpoints_compared`.
- Exactly **one** fixture in the whole `bin/` directory shows a guest-state divergence: **`vex`**.
  It fails on output *as well as* state, and it is **deliberately excluded** from
  `recompile_test.py` (`tests/vex/vex_test.py` asserts that exclusion, check
  `suite/not-differential`).
- That single divergence is a **defect in the Unicorn reference, not in the recompiled
  candidate**. The candidate is the SDM-correct side.

So: the guest-state gate is working and is not vacuous, but it is not currently failing anything
that the end-to-end suite exercises.

---

## 2. Method (exact commands)

Fixture build (23 executables + `fixtures.sha256`), exit 0:

```
cd tests/fixtures/apps && ./build.sh
# ...
# built .../bin/unsupported_import.exe (negative)
# wrote .../bin/fixtures.sha256
# [exit code: 0]
```

Per-fixture sweep (a driver in `/tmp`, one project dir per fixture, results in `/tmp/ss-results/`):

```
./build/recomp-studio translate tests/fixtures/apps/bin/<name>.exe \
    --target macos-arm64 --output /tmp/ss-<name>
./build/recomp-studio build   /tmp/ss-<name>
./build/recomp-studio verify  /tmp/ss-<name> --json
```

Staleness check — the binary was **not** stale, so no rebuild was needed:

```
$ cmake --build build
[0/1] Re-running CMake...
-- Configuring done (0.2s)
-- Generating done (0.0s)
-- Build files have been written to: .../build
ninja: no work to do.
[build exit: 0]
```

Disassembly used `python3` + `capstone` 5.0.7 + `pefile` over the PE's memory-mapped image
(same approach as `reports/tools/crosscheck_decoder.py`), resolving
`virtual address = image_base (0x140000000) + section RVA`.

---

## 3. Results table

`ckpts` = `checkpoints_compared`; `cand_lines` = lines in the candidate's
`reports/candidate-checkpoints.txt`. In every row `ckpts == cand_lines`, i.e. the candidate
recorded no more checkpoints than the reference reached, so the compared window is the
candidate's full run and is not truncated by the reference.

| fixture | status | outputs_match | state_match | ckpts | cand_lines | first divergence diagnosis |
|---|---|---|---|---|---|---|
| aliasing | pass | true | true | 4 | 4 | — |
| arith | pass | true | true | 178 | 178 | — |
| bitops | pass | true | true | 3 | 3 | — |
| byteops | pass | true | true | 2 | 2 | — |
| calls | pass | true | true | 3 | 3 | — |
| eflags | pass | true | true | 14 | 14 | — |
| flagprobe | pass | true | true | 414 | 414 | — |
| heap | pass | true | true | 10 | 10 | — |
| memory | pass | true | true | 3 | 3 | — |
| packed | pass | true | true | 40 | 40 | — |
| pe32_abi | pass | true | true | 4 | 4 | — |
| pe32_arith | pass | true | true | 189 | 189 | — |
| pe32_simd_convert | pass | true | true | 53 | 53 | — |
| simd_convert | pass | true | true | 31 | 31 | — |
| snake | pass | true | true | 8 | 8 | — |
| teb32 | pass | true | true | 1 | 1 | — |
| tictactoe | pass | true | true | 108108 | 108108 | — |
| vecmove | pass | true | true | 2 | 2 | — |
| wide | pass | true | true | 17 | 17 | — |
| x87 | pass | true | true | 10 | 10 | — |
| **vex** | **fail** | **false** | **false** | **3** | **3** | `checkpoint 2: the guest instruction stream differs at 0x1400010dd (reference 0x1400011e8)` |
| unsupported_import | fail | false | false | 0 | 0 (no file) | *(negative fixture; `reference_completed: false`)* |
| unsupported_instruction | translate fail | — | — | — | — | *(negative fixture; `error: unsupported instruction 'rdmsr' at 0x1400010beull`)* |

Counts: **20 pass, 2 fail** over all 23 built executables. Restricted to the 19 fixtures the
end-to-end test requires: **19/19 pass**.

`unsupported_import` and `unsupported_instruction` are the two *negative* fixtures
(`FIXTURES_NEGATIVE` in `build.sh`) and are expected to fail; they are not part of
`recompile_test.py` and are covered by `negative_inputs`.

---

## 4. The one real divergence: `vex`

### 4.1 Raw output of the failing command

```
$ ./build/recomp-studio verify /tmp/ss-vex --json
{"status":"fail","reference_completed":true,"candidate_completed":true,
 "outputs_match":false,"checkpoints_compared":3,"state_match":false,
 "state_diagnosis":"checkpoint 2: the guest instruction stream differs at 0x1400010dd (reference 0x1400011e8)",
 "candidate_exit_code":0,"executed_instructions":3118,
 "reference_bytes":172,"candidate_bytes":171,"unsupported_mnemonics":[]}
```

Note the diagnosis is an **address** divergence, not a register or flags divergence: the
comparison tests address equality before register equality, so the differing register at that
checkpoint is never reported. The stream lengths differ (172 vs 171 bytes), so `outputs_match`
is already false; the state divergence is a *second* symptom of the same cause.

### 4.2 Named x86 instructions

Disassembled from the original `tests/fixtures/apps/bin/vex.exe` (PE32+, image base
`0x140000000`, `.text` at RVA `0x1000`, size `0x7e0`):

```
0x14000111c: 4801c0                add    rax, rax            <- checkpoint 1, AGREES
0x1400010dd: 4d89cb                mov    r11, r9            <- checkpoint 2, CANDIDATE is here
0x1400011e8: 4c8d4c2450            lea    r9, [rsp + 0x50]   <- checkpoint 2, REFERENCE is here
```

Both checkpoint-2 addresses live inside the same integer-printing helper (`outi`). The
reference's address is the instruction immediately after the `call rbx` at `0x1400011e6`,
which is on the **negative-number path** of that helper:

```
0x1400011c0: b9f5ffffff            mov    ecx, 0xfffffff5     ; -11
0x1400011c5: 4c89a42490000000      mov    qword ptr [rsp+0x90], r12
0x1400011cd: 488b1d7c1e0000        mov    rbx, qword ptr [rip+0x1e7c]
0x1400011d4: 488d7c244c            lea    rdi, [rsp+0x4c]
0x1400011d9: c644244c2d            mov    byte ptr [rsp+0x4c], 0x2d   ; '-'
0x1400011de: c744245000000000      mov    dword ptr [rsp+0x50], 0
0x1400011e6: ffd3                  call   rbx                          ; emit "-"
0x1400011e8: 4c8d4c2450            lea    r9, [rsp + 0x50]             ; <- REFERENCE checkpoint 2
```

The candidate's address `0x1400010dd` is the entry setup of the decimal digit loop
(`mov r11, r9` / `xor r10d, r10d` / … / `mul r12` / `add rax, rax`).

### 4.3 The instruction that actually differs — and proof of which side is wrong

Scanning `.text` for VEX encodings gives the fixture's AVX instructions; the three-operand XOR is:

```
0x140001638: c5f1efda             vpxor   xmm3, xmm1, xmm2
0x14000163c: c5fa7f9c24d0000000   vmovdqu xmmword ptr [rsp + 0xd0], xmm3
```

`vex.c` builds the operands so the SDM-correct result is computable by hand:

```c
left[i]  = (unsigned char)(0xf0 - index);   /* 0xf0, 0xef, ... */
right[i] = (unsigned char)(0x0f + index);   /* 0x0f, 0x10, ... */
```

`(0xf0 - i) ^ (0x0f + i) == 0xff` for every `i`, so the correct `xored[16]` is **16 × 0xff**.
Folding that with `checksum = checksum*31 + byte` (signed 64-bit wraparound) gives
`6175760664974581504` — exactly what the candidate prints. Testing the plausible ways Unicorn
could get it wrong:

| hypothesis for `xored[16]` | folded checksum | matches |
|---|---|---|
| `src1 ^ src2` (SDM-correct, all `0xff`) | **6175760664974581504** | **candidate** |
| `src2` alone (`right[i] = 0x0f+i`) | **-6300853929389498616** | **reference** |
| `src1` alone (`left[i] = 0xf0-i`) | -5970129479345471496 | neither |
| zeros | 0 | neither |

The reference's printed value is reproduced **exactly** by assuming Unicorn's
`vpxor xmm3, xmm1, xmm2` wrote `src2` into the destination with no XOR performed at all.

Measured output difference:

```
candidate: vpxor_checksum=6175760664974581504     <- SDM-correct
reference: vpxor_checksum=-6300853929389498616    <- fold of src2
```

### 4.4 Causal chain (what is proven vs. inferred)

1. **Proven (arithmetic):** at `0x140001638`, the candidate's `vpxor` yields `0xff × 16` and the
   reference's yields `src2`; the two folded checksums match those two inputs exactly.
2. **Proven (code):** the differing checksum is printed by `outi`, and `outi` has a sign-dependent
   branch (`0x1400011d9` writes `'-'`; taken only for negative values). The candidate's value is
   positive, the reference's is negative.
3. **Inferred (not traced):** that sign difference is what makes the two instruction streams
   differ in length, so their counters drift and checkpoint 2 lands on different addresses —
   the reference still inside the minus-print block, the candidate already in the digit loop.
   I did **not** capture either instruction stream, so this last step is consistent-with-evidence
   rather than directly observed.

---

## 5. Grouping: one root cause, and it is on the reference side

**One root cause: the Unicorn reference mis-emulates three-operand VEX `vpxor`.**

Evidence that this is known and intentional, not a new finding:

- `tests/fixtures/apps/vex.c` carries a `KNOWN REFERENCE LIMITATION` block naming Unicorn
  issue #1074 ("incorrect emulation of most VEX instructions", which names `vpxor`) and PR #1658
  ("YMM isn't supported in qemu upstream at all"), and states the expected reference value
  `-6300853929389498616` and the expected program value `6175760664974581504` — both of which I
  measured.
- `tests/vex/vex_test.py` documents the same table, asserts those literals, and includes the
  check `suite/not-differential`, which **fails if `vex` is ever added to `recompile_test.py`**.
- The fixture is therefore verified *by value*, not differentially, and `vex_encoding_values`
  passes (`Test #12 ... Passed 14.57 sec`).

**There is no second root cause and no candidate-side state divergence anywhere in the corpus.**
Grouping by symptom:

| group | fixtures | verdict |
|---|---|---|
| VEX/AVX reference mis-emulation | `vex` (1) | reference is wrong; candidate SDM-correct; excluded from the differential suite by design |
| expected negative fixtures | `unsupported_import`, `unsupported_instruction` (2) | fail by design (`FIXTURES_NEGATIVE`) |
| no divergence | the other 20 | `outputs_match: true`, `state_match: true` |

Consequence for the stated task: since `vex` is not in `recompile_test.py`'s fixture list, the
new state gate currently has **no failing subject** in that test. The gate is nonetheless
exercised non-vacuously by `guest_state_checkpoints` (`tests/verification/guest_state_test.py`,
registered in `CMakeLists.txt` at line 110), which mutates `checkpoint.flags` in
`runtime/recomp_runtime.cpp` and asserts that a state-only difference still fails verification.

---

## 6. Reproducibility and tree state

The sweep was run **twice**; the two summaries are byte-identical:

```
$ diff <(sort /tmp/ss-results/summary.txt) <(sort /tmp/ss-results2/summary.txt)
IDENTICAL: all 23 fixture results reproduce byte-for-byte
```

The tree is **being edited concurrently by other team members**, so all findings are pinned to:

```
HEAD 87a8aa1 (feature/x86-x64-arm64-mvp), working tree dirty:
 M CMakeLists.txt, apps/cli/main.cpp,
 M core/verification/differential_harness.cpp, core/verification/differential_harness.hpp,
 M runtime/recomp_runtime.cpp, runtime/recomp_runtime.hpp
 ?? .commandcode/, tests/verification/

sha256  build/recomp-studio                            7481c606c4c19132a49f22656214097ca49504e1f6cb215b03c293295b594aac
sha256  runtime/recomp_runtime.cpp                     f4f5c336817cd82dcbd4934ed65bfeb4fee72177e03ff22e3719236dccc9d447
sha256  core/verification/differential_harness.cpp     91199bb6857ba14e577d24b9119c3cc78bdceb563bd34563e1c4d8ec651ab597
sha256  apps/cli/main.cpp                              ab9f42527a620515125c706773bbd2ac6b61e4b2f7d7c6a04d27b7998d6b96dd
sha256  CMakeLists.txt                                 9b5941a7fe9b3557ccb12af9ea733d57855a2aab11e3880aafaa9126e6a107ac
```

`CMakeLists.txt` was modified by another member at `16:17:09` (adding `guest_state_checkpoints`)
*after* my first `ctest -N`, which listed 13 tests; it now lists 14. The end-to-end test's own
fixture list was unchanged throughout.

---

## 7. What I did NOT determine

- **Why the premise holds that `fixture_recompile_end_to_end` is failing.** It passes here,
  twice, on the current binary. If a failure was observed earlier, it predates the uncommitted
  changes now in the tree (the binary is newer than every modified source: `ninja: no work to do`),
  or it depends on a state I could not reproduce. I did not bisect the history to find a commit
  where it failed.
- **The reference's guest-instruction count.** `verify --json` reports `executed_instructions`
  from `ReferenceState::instruction_count`, which is incremented *before* the import-thunk
  early-return (`differential_harness.cpp:210`), while checkpoints use the thunk-excluded
  `guest_instruction_count` (`:223`). So `executed_instructions / 1000 + 1` overestimates the
  reference's checkpoint count by the thunk count (e.g. `flagprobe`: 440 estimated vs 414
  compared). I could not measure the reference's true guest count from the JSON, so I cannot say
  from that alone whether a candidate's checkpoint file is short because it ran fewer guest
  instructions or because the reference ran extra thunk calls. In all cases the compared
  checkpoints matched on address, so the counters agree at least over the compared window.
- **The real-application corpus.** `real_application_corpus` **skips**:
  `SKIP: no applications found under <RECOMP_APPS_DIR unset>`. No real Windows application was
  exercised against the state gate, so "no divergence" is a statement about the 23 fixtures only.
- **Whether `vex` diverges on state before it diverges on output.** The diagnosis names an
  address mismatch at checkpoint 2; the first *value* difference (`vpxor_checksum`) is not
  localised to a checkpoint by the tooling, and the register at checkpoint 2 is never reported
  because the address check short-circuits it.
- **I did not trace either instruction stream**, so §4.4 step 3 is inference. Producing a real
  trace (the harness has `compare_execution_traces`) would settle it.
- **I did not modify any source file.** The only file written is this report; all scratch work
  lives in `/tmp` (`/tmp/ss-*.sh`, `/tmp/ss-disasm.py`, `/tmp/ss-vexscan.py`, `/tmp/ss-results*/`).
- **I did not run `guest_state_checkpoints`** in this session, because it temporarily rewrites
  `runtime/recomp_runtime.cpp` and another member was editing that file concurrently. It is
  registered and should be run by the Lead on a quiesced tree.
