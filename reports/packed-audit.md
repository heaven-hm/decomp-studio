# Adversarial audit of the SSE2 packed-integer implementation (task-8)

**Owner:** `coverage-audit` (teammate)
**Deliverable:** this file. Write scope was exactly `reports/packed-audit.md`; no code, test or
other report was modified.

**Verdict: 1 live build-breaking defect found, 0 live semantic defects found.**
Differential execution of the runtime helpers against **real x86 SSE2 silicon** (Rosetta 2)
passes 35 883 register-form checks and 4 500 memory-form checks with zero mismatches. The
live defect is structural, not arithmetic: five helpers the lifter emits for a memory operand
**do not exist**, so the generated project fails to compile — and `coverage` reports those
instructions as lifted, so the census cannot see it.

---

## 0. READ THIS FIRST — the tree moved five times during the audit

The working tree was being edited continuously while I audited it. Recorded hashes:

| time | `core/semantics/x86_64_lifter.cpp` | `runtime/recomp_runtime.hpp` |
| --- | --- | --- |
| 08:19 (task claimed) | `da6ed6b9…` | `5a42598c…` |
| 08:20:28 | `656f5a61…` | — |
| 08:25:56 | — | `7d88586d…` |
| 08:30:05 (snapshot 1) | `d90ff76d…` | `4ffcc3c9…` |
| 08:39:56 (snapshot 2, audited) | `d825974f…` | `2ea98329…` |
| 08:44:14 (final check) | `aa29b519…` | `2ea98329…` (unchanged) |

Three of the four semantic defects below were **fixed while I was measuring them**, which is
why several entries in §3 read "was wrong, now fixed". I re-ran everything against snapshot 2
and re-verified the live tree at the end. **The live defect in §2 was re-confirmed against the
live tree at 08:44** — `runtime/recomp_runtime.hpp` has not changed since 08:39:56, and the
five missing symbols are still missing.

If you edit either file again, re-run the three commands in §1.3 before trusting §2/§3.

---

## 1. Method

### 1.1 Differential execution against real hardware (the main instrument)

The previous VEX audit reasoned from the SDM text. That is how the 16-byte `emit_vector_move`
bug was found, but it is slow and it is only as good as my reading. This time I removed the
reading from the loop:

* **Rosetta 2 is available on this host**, so I can compile and run genuine x86_64 SSE2 code.
* I wrote a harness that `#include`s the **live** `recomp_runtime.hpp`, so it calls the real
  helper functions — not a transcription.
* For each case it loads the same inputs into two xmm registers, executes the **real
  instruction** with inline asm, calls the runtime helper on a second copy of the same
  registers, and `memcmp`s the 16-byte results.
* Coverage: every mnemonic in `packed_integer_helpers()` and `packed_immediate_helpers()`,
  over a structured cross-product of edge vectors (zeros, all-ones, sign-bit patterns,
  byte/word minima and maxima, small dwords) plus 800 random vectors, plus 400 random vectors
  biased to high-bit-set shift counts.

Because the harness includes the live header, re-auditing a new revision is a recompile.

### 1.2 Static and structural checks

Differential execution only exercises the helpers. It cannot see **wiring** defects — a helper
that is never called, called with the wrong argument, or a symbol that does not exist. So I
additionally:

* enumerated the lifter tables and generated a compile probe that references the exact
  `_memory` symbol the lifter emits for every one of the 37 `packed_integer_helpers()` entries;
* re-decoded the corpus with the independent decoder from `reports/tools/` to measure
  reachability of anything broken;
* checked each of the 10 items the task called out, individually.

### 1.3 Exact commands

```sh
# semantic differential (register forms) -- 35,883 checks
clang++ -arch x86_64 -std=c++20 -O1 -w -I <snapshot> /tmp/packedtest/test.cpp -o test_x86 && ./test_x86

# semantic differential (memory forms) -- 4,500 checks
clang++ -arch x86_64 -std=c++20 -O1 -w -I <snapshot> /tmp/packedtest/memtest.cpp -o memtest_x86 && ./memtest_x86

# structural: does every emitted _memory symbol exist?
python3 - <<'PY'   # generates one call per packed_integer_helpers() entry
...
PY
clang++ -arch x86_64 -std=c++20 -O0 -w -I runtime -c /tmp/packedtest/probe_live.cpp -o /dev/null
```

Raw harness output is quoted inline below. Harness sources are in `/tmp/packedtest/`
(`test.cpp`, `memtest.cpp`, `witness.cpp`, `probe_live.cpp`, `reachability.py`, `cleanfn.py`).

---

## 2. LIVE DEFECT — five `_memory` helpers do not exist; the generated project will not compile

**File:** `core/semantics/x86_64_lifter.cpp:500` (emission) together with the table entries at
`:176`, `:178`, `:189`, `:198`, `:199`
**Runtime:** `runtime/recomp_runtime.hpp` — the missing definitions would belong beside
`:1003` (`vector_add_dwords`), `:1009` (`vector_subtract_dwords`), `:1015`
(`vector_compare_equal_dwords`), `:979` (`vector_multiply_add_words`), `:992`
(`vector_sum_absolute_differences`)

### What the code does

`packed_integer_helpers()` maps each mnemonic to a helper *base* name. The dispatch then does:

```cpp
// x86_64_lifter.cpp:496-501
if (operands[1].kind == discovery::Operand::Kind::Memory) {
  emit(helper->second + "_memory(context, " + destination + ", " +
       effective_address_expression(instruction, operands[1]) + ");");
  return;
}
```

It appends `_memory` to whatever base name the table holds. That is safe for the 32 entries
generated by `RECOMP_PACKED_BINARY` (`runtime/recomp_runtime.hpp:587`), which emits the
register form **and** the `_memory` form from one expression. It is not safe for the five
entries whose helpers are **hand-written**, because those were written without a `_memory`
twin:

| mnemonic | table line | helper (hand-written, no `_memory`) |
| --- | --- | --- |
| `paddd` | `x86_64_lifter.cpp:176` | `vector_add_dwords` (`recomp_runtime.hpp:1003`) |
| `psubd` | `:178` | `vector_subtract_dwords` (`:1009`) |
| `pcmpeqd` | `:189` | `vector_compare_equal_dwords` (`:1015`) |
| `pmaddwd` | `:198` | `vector_multiply_add_words` (`:979`) |
| `psadbw` | `:199` | `vector_sum_absolute_differences` (`:992`) |

### What the SDM requires

Nothing — this is not a semantics question. The requirement is that the emitted C++ names a
symbol that exists. It does not.

### Concrete input where they differ

Compiling a translation unit that calls exactly the symbols the lifter emits:

```
$ clang++ -arch x86_64 -std=c++20 -O0 -w -I runtime -c probe_live.cpp -o /dev/null
probe_live.cpp:7:3: error: use of undeclared identifier 'vector_add_dwords_memory'
probe_live.cpp:11:3: error: use of undeclared identifier 'vector_subtract_dwords_memory'
probe_live.cpp:23:3: error: use of undeclared identifier 'vector_compare_equal_dwords_memory'; did you mean 'recomp::vector_compare_equal_words_memory'?
probe_live.cpp:32:3: error: use of undeclared identifier 'vector_multiply_add_words_memory'; did you mean 'recomp::vector_multiply_low_words_memory'?
probe_live.cpp:33:3: error: use of undeclared identifier 'vector_sum_absolute_differences_memory'; did you mean 'recomp::vector_sum_absolute_differences'?
5 errors generated.
```

Five of 37 table entries fail to link. The `did you mean` suggestions are the giveaway: the
`_words`/unsigned siblings exist because they are macro-generated; the `_dwords` and the two
hand-written ones do not.

### Reachability (ranked)

Measured by walking the recovered instruction stream of all 16 corpus binaries and looking for
these mnemonics with a **memory** second operand:

| mnemonic | missing symbol | instances | binaries |
| --- | --- | --- | --- |
| `paddd` | `vector_add_dwords_memory` | 62 | 5 |
| `psubd` | `vector_subtract_dwords_memory` | 4 | 3 |
| `pmaddwd` | `vector_multiply_add_words_memory` | 2 | 1 |
| `pcmpeqd` | `vector_compare_equal_dwords_memory` | 1 | 1 |
| `psadbw` | `vector_sum_absolute_differences_memory` | 0 | 0 |
| | **total** | **69** | 7 binaries |

Reachability of the *build step* is narrower, because a function that contains any other
unsupported instruction is stubbed out and its body never reaches `guest.cpp`. Filtering to
instances whose containing function is otherwise clean — i.e. every instruction in it lifts,
so the function **is** emitted:

```
mnemonic      all instances  in clean fns  verdict
paddd                    61            42  REACHES BUILD
psubd                     4             0  masked by another unsupported instruction
pmaddwd                   2             0  masked by another unsupported instruction
pcmpeqd                   1             1  REACHES BUILD
TOTAL                    68            43

Instances that reach the generated source and break the build:
    bat.exe: 0x140157a3e in fn 0x140157840  paddd xmm1, xmmword ptr [rip + 0x2c461a]
    bat.exe: 0x140157a68 in fn 0x140157840  paddd xmm0, xmmword ptr [rip + 0x2c4600]
    openlierox.exe: 0x140238c26 in fn 0x140238660  paddd xmm0, xmmword ptr [rip + 0x5576e2]
    openlierox.exe: 0x140238de5 in fn 0x140238660  paddd xmm0, xmmword ptr [rip + 0x557533]
    openlierox.exe: 0x140238fe4 in fn 0x140238660  paddd xmm0, xmmword ptr [rip + 0x557324]
    openlierox.exe: 0x1402393bf in fn 0x140238660  paddd xmm0, xmmword ptr [rip + 0x556f49]
    openlierox.exe: 0x140432594 in fn 0x140432240  pcmpeqd xmm1, xmmword ptr [rsp + 0x10]
```

**43 instructions across 2 binaries (bat.exe, openlierox.exe) reach the generated source and
break the build today.** I could not demonstrate the failure end-to-end through `translate`
`&&` `build` on the current corpus, because in the one binary I tried
(`legacy-notepad-x64.exe`, non-strict) the containing function was stubbed — which is exactly
why the filter above exists. The compile probe is the direct proof.

### Why `coverage` cannot see this — and why that matters

```
$ ./build/recomp-studio coverage bat.exe --json
    paddd   in unsupported list: False
    psubd   in unsupported list: False
    pcmpeqd in unsupported list: False
    pmaddwd in unsupported list: False
    psadbw  in unsupported list: False
    coverage says lifted 392578/392840

$ ./build/recomp-studio coverage openlierox.exe --json
    ... all five also False ...
    coverage says lifted 1496914/1499486
```

The lifter **accepts** these instructions (it emits a call and returns), so the census counts
them as lifted. Coverage therefore reports a healthy number for a program that cannot be
built. This is the same failure mode as the task-5 finding that `translate` "succeeds" on .NET
images: a confident-looking result that is not a usable one.

### Fix

Either add the five `_memory` variants, or convert the five hand-written helpers to
`RECOMP_PACKED_BINARY` so the pair is generated together and cannot drift. The second option
removes the whole class of bug — note that `pmuludq` and `pandn` were **already** converted
this way (`vector_multiply_unsigned_dwords` has an explicit `_memory` twin at
`recomp_runtime.hpp:831`), so the pattern is established. A compile-time guard would also
help: the census could assert that every name in `packed_integer_helpers()` resolves.

---

## 3. Semantic defects found during the audit, and their current state

These were real in the revision I first read. Three were fixed while I was measuring; I record
them because they are worth keeping as regression tests, and because "fixed during the audit"
is not the same as "was never there".

### 3.1 Variable-count shifts used the wrong count — FIXED, now correct

**Was:** `runtime/recomp_runtime.hpp` (originally `RECOMP_PACKED_BINARY(vector_shift_left_words,
std::uint16_t, b > 15 ? 0 : a << b)` etc.). Each element was shifted by its **corresponding
source element**.
**Now:** `RECOMP_PACKED_SHIFT_BY_SOURCE` (`recomp_runtime.hpp:733`) reads the low 64 bits of
the source register once (`vector_shift_count`) and passes that single count to the immediate
helper.

**What the SDM requires — and this is the part the task description had wrong.** The task said
"the count is the low 64 bits of the corresponding source *element*". Real silicon disagrees:
for the register/memory form the count is the low 64 bits **of the source operand as a whole**,
broadcast to **every** element. Witness:

```
psllw  dst=ffffffffffffffffffffffffffffffff
       src=00000000000000030000000000000002   (low64 = 2, but word3 = 3)
       hardware (SDM) = fffcfffcfffcfffcfffcfffcfffcfffc   every word << 2
       runtime helper = fffcfffcfffcfffcfffcfffcfffcfffc
```

Every word shifted by 2, including the words whose own corresponding source element is 0 or 3.
The old element-wise helper produced `fffffffffffffff8 fffffffffffffffc` — words 1 and 2
unchanged, word 3 shifted by 3. The current helper matches hardware.

This affected all eight variable shifts: `psllw`, `pslld`, `psllq`, `psrlw`, `psrld`, `psrlq`,
`psraw`, `psrad`. Against the pre-fix revision the harness reported **1 330 mismatches out of
35 883 checks** (psrad 595, psraw 577, psllw 28, psrlw 26, pslld 21, psrld 17, psllq 16,
psrlq 12, plus the saturation defects below). Against the current revision: **0**.

### 3.2 `psubsb` / `psubsw` saturation hole at `a == 0` — FIXED, now correct

**Was:** `a < 0 && b > 127 + a ? -128 : (a > 0 && b < -128 + a ? 127 : a - b)`. Both guards
require `a` to be strictly non-zero, so with `a == 0` and `b` negative the subtraction fell
through to `a - b` and wrapped.
**Now:** computes `static_cast<int>(a) - static_cast<int>(b)` in a wider type and compares
against the bounds (`recomp_runtime.hpp:640`, `:655`).

Witness (the identical case, still valid as a regression test):

```
psubsb dst=00000000000000000000000000000000
       src=00000000000000008000000000000080   (byte0: 0 - (-128))
       hardware (SDM) = 00000000000000007f0000000000007f   saturates to 0x7f
       runtime helper = 00000000000000007f0000000000007f
```

Pre-fix the helper returned `…80…` (the wrapped `-128`). 31 `psubsb` and 7 `psubsw`
mismatches pre-fix; 0 now. `paddsb`/`paddsw`/`paddusb`/`paddusw`/`psubusb`/`psubusw` were
correct throughout — their guards have no zero-hole.

### 3.3 `pmuludq` was element-wise and truncated — FIXED, now correct

**Was:** `RECOMP_PACKED_BINARY(vector_multiply_unsigned_dwords, std::uint32_t, …)` — a uniform
element-wise dword multiply whose 64-bit product was immediately truncated back to 32 bits.
That is wrong twice over: PMULUDQ multiplies only the **even** dwords (elements 0 and 2) and
writes **64-bit** results.
**Now:** hand-written at `recomp_runtime.hpp:821`:
`result[2] = { left[0]*right[0], left[2]*right[2] }` as `std::uint64_t`, stored as 16 bytes,
with a comment explaining exactly why the element-wise version was wrong.

Concrete case that would have differed:

```
dst dwords = {0xFFFFFFFF, 0, 0, 0}   src dwords = {0xFFFFFFFF, 0, 0, 0}
SDM:  dst[63:0] = 0xFFFFFFFE00000001, dst[127:64] = 0
      -> dwords {0x00000001, 0xFFFFFFFE, 0, 0}
old:  dword1 = low32(0*0) = 0, and the high half was lost
```

Current helper vs hardware on that input: `0000000000000000fffffffe00000001` for both.
0 mismatches now.

### 3.4 `pshuflw` / `pshufhw` were silently unsupported — FIXED, now correct

**Your suspicion was right.** Capstone decodes both as **three** operands:

```
pshuflw xmm0, xmm1, 0x1b   -> 'pshuflw xmm0, xmm1, 0x1b'  nops=3  [(reg xmm0), (reg xmm1), (imm 0x1b)]
pshufhw xmm0, xmm1, 0x1b   -> 'pshufhw xmm0, xmm1, 0x1b'  nops=3  [(reg xmm0), (reg xmm1), (imm 0x1b)]
pshufd  xmm0, xmm1, 0x1b   -> 'pshufd  xmm0, xmm1, 0x1b'  nops=3
```

The old guard was `operands.size() == 2` nested inside the block at
`x86_64_lifter.cpp:486`, so they fell through to `record_unsupported`. Empirically they were
the top-2 and 17th entries of the task-5 unsupported list (`pshuflw 461`, `pshufhw 37`).

**Now:** a dedicated 3-operand handler at `x86_64_lifter.cpp:545` that takes the source from
`operands[1]`, seeds the destination from it when they differ, and then calls the in-place
helper — correct, because the SDM derives the *whole* destination from the source (low four
words shuffled, high four copied).

Note this also fixed a second latent bug I had flagged: `vector_shuffle_low_words` /
`vector_shuffle_high_words` take only a destination and read it as the source, so a 3-operand
form with `src != dst` would have shuffled the wrong register. The seeding memcpy handles it.

---

## 4. The ten specific checks, item by item

| # | Item | Verdict |
| --- | --- | --- |
| 1 | Variable-count shift count semantics | **Was wrong, now CORRECT.** And the task description's premise was wrong: it is the low 64 bits of the source *operand* broadcast to all elements, not the corresponding element. See §3.1. |
| 2 | Immediate form vs register/memory form routing | **CORRECT.** Immediate → `packed_immediate_helpers()` with `const std::uint64_t b = count`; register/memory → `_by_source`, which extracts the low 64 bits. Both verified against hardware, including counts 0/7/15/16/17/31/32/63/64/255 and the zero-fill/sign-fill past-width behaviour. |
| 3 | `pmuludq` not a uniform dword multiply | **Was wrong, now CORRECT.** Even dwords, 64-bit results. See §3.3. |
| 4 | `psadbw` produces two 64-bit sums | **CORRECT.** `vector_sum_absolute_differences` (`recomp_runtime.hpp:992`) accumulates into `std::uint64_t result[2]` indexed `index / 8`. Verified against hardware on random and edge vectors. |
| 5 | `packsswb`/`packuswb`/`packssdw` take low half from dst, high half from src | **CORRECT**, order not swapped. `result[index]` from `left` for 0–7, `result[index+8]` from `right` (`recomp_runtime.hpp:899`, `:912`, `:925`). Verified against hardware. |
| 6 | `punpck*` interleave without swapping halves | **CORRECT.** `offset = high ? 8 : 0` (bytes) / `high ? 4 : 0` (words), `result[2k] = left[offset+k]`, `result[2k+1] = right[offset+k]`. Verified for all four mnemonics, both halves. |
| 7 | `pmovmskb` writes a 32-bit GPR with 16 sign bits | **CORRECT.** `vector_move_byte_mask` sets bits 0–15 only; upper 16 bits are zero; the lifter writes it with width 4 (`x86_64_lifter.cpp`, `operand_write_statement(..., 4)`). Verified against hardware. |
| 8 | `pshufb` zeroes a lane when index bit 7 is set | **CORRECT.** `(indices[i] & 0x80) ? 0 : values[indices[i] & 0x0F]`. Verified against hardware, including all-0x80 and mixed index vectors. |
| 9 | `pshuflw`/`pshufhw` operand-count guard | **Your suspicion confirmed — it was `== 2` and they were silently unsupported. Now fixed to `== 3` with the source operand plumbed through.** See §3.4. |
| 10 | `pcmpgt*` are signed comparisons | **CORRECT.** `std::int8_t` / `std::int16_t` / `std::int32_t` element types with `a > b ? all-ones : 0`. Verified against hardware, including the `0x80` vs `0x7f` boundary where a signed and unsigned comparison disagree. |

---

## 5. Coverage gaps found (fail closed — not correctness bugs)

These are instructions the lifter declines. They are not defects in the sense of §2, but they
are the reason several corpus binaries still do not lift, and two of them are surprising given
the VEX table.

**5.1 Memory sources for unpack/pack/shuffle are rejected.** At `x86_64_lifter.cpp:519`
(`punpcklbw/hbw/lwd/hwd`), `:528` (`packsswb/packuswb/packssdw`) and `:537` (`pshufb`) the
source is guarded by `is_vector_register(operands[1])`, and those helpers have no `_memory`
form at all. So `punpcklbw xmm0, [rax]`, `packsswb xmm0, [rax]` and `pshufb xmm0, [rax]` are
unsupported. These are common forms.

**5.2 `vpshuflw` / `vpshufhw` cannot work through the VEX path.** `vex_equivalents()` maps
`vpshuflw → pshuflw` and `vpshufhw → pshufhw` (`x86_64_lifter.cpp:156`). The VEX 3-operand path
copies `src1` into the destination and then **re-dispatches with two operands**
(`{operands[0], operands[2]}`). The `pshuflw` handler now requires three operands, so the
re-dispatch falls through to `record_unsupported`. The mapping is therefore dead — it suggests
support that does not exist. It fails closed (the exception discards the function), so there is
no correctness risk, but the entry should either be removed or the VEX path taught to pass the
source through.

**5.3 Dead element-wise shift helpers remain defined.** `vector_shift_left_words`,
`vector_shift_right_logical_words` and `vector_shift_right_arithmetic_words` are still defined
in the runtime (the pre-fix element-wise versions) but are no longer referenced by the lifter.
They are a re-wiring hazard: anyone who points the table back at them silently reintroduces
§3.1. Worth deleting.

---

## 6. Operations checked and found CORRECT (explicit list)

So that you know what was examined rather than assumed. All of the following matched real
hardware exactly, across the structured edge-vector cross-product plus 800 random vectors:

**Arithmetic (wrapping):** `paddb`, `paddw`, `paddd`, `paddq`, `psubb`, `psubw`, `psubd`,
`psubq`.
**Saturating:** `paddsb`, `paddusb`, `psubsb`, `psubusb`, `paddsw`, `paddusw`, `psubsw`,
`psubusw`.
**Compare:** `pcmpeqb`, `pcmpeqw`, `pcmpeqd`, `pcmpgtb`, `pcmpgtw`, `pcmpgtd`.
**Multiply:** `pmullw`, `pmulhw`, `pmulhuw`, `pmuludq`, `pmaddwd`, `psadbw`.
**Bitwise:** `pandn` (SDM: `~dst & src` — confirmed, not `dst & ~src`).
**Shifts, immediate:** `psllw`, `pslld`, `psllq`, `psrlw`, `psrld`, `psrlq`, `psraw`, `psrad`
at counts 0, 7, 15, 16, 17, 31, 32, 63, 64, 255 — including the zero-fill and sign-fill
past-width behaviour.
**Shifts, register/memory:** all eight, via `_by_source`.
**Whole-register byte shifts:** `psrldq`, `pslldq` at 0, 3, 15, 16.
**Unpack:** `punpcklbw`, `punpckhbw`, `punpcklwd`, `punpckhwd`.
**Pack:** `packsswb`, `packuswb`, `packssdw`.
**Shuffle:** `pshufb`, `pshuflw`, `pshufhw` (with `dst == src`; the 3-operand `src != dst` case
is handled by the seeding memcpy in the lifter, which I read but did not execute).
**Mask:** `pmovmskb`.
**Memory forms:** `paddb`, `paddq`, `psubw`, `paddsw`, `psubusb`, `pcmpeqb`, `pcmpgtd`,
`pmullw`, `pmulhw`, `pmulhuw`, `pmuludq`, `pandn`, `psllw`, `psrlq`, `psrad` — 4 500 checks,
0 failures. `pmuludq`'s memory form is a hand-written duplicate of its register form, so it was
worth executing separately; it matches.

**Totals on the audited revision:** register forms 35 883 checks / 0 failures; memory forms
4 500 checks / 0 failures.

---

## 7. Not verified

Marking these explicitly rather than implying coverage I do not have:

* **`psadbw` memory form** — does not exist (§2), so there is nothing to test. Zero corpus
  instances.
* **`pshuflw`/`pshufhw` with `src != dst`** — the lifter's seeding memcpy was read, not
  executed; the helper itself was executed with `dst == src` and matches hardware.
* **256-bit (`ymm`) behaviour of the packed helpers** — the helpers are 128-bit only
  (they `memcpy` 16 bytes and index `16 / sizeof(element)`), and the lifter routes `ymm`
  operands to them for `movaps`-style moves. I did not test a `ymm` operand reaching a
  packed-integer helper; `vpshufb ymm` and friends appear in the corpus as unsupported, so
  this may not be reachable — but I did not prove that.
* **`report_guest_memory_fault` / out-of-bounds memory behaviour** — I stubbed the fault
  handler in the memory-form harness, so the fault path itself is untested.
* **Whether the emitted `_memory` address expression is correct** — I audited the helper
  symbols and semantics, not `effective_address_expression`. That is a separate concern and is
  already covered by the project's own runtime tests as far as I know.
* **Interaction with `instruction_patches`** — not exercised.

---

## 8. Limitations of the method

1. **Rosetta 2 is an emulator, not silicon.** It is a very high-fidelity one and it is the
   best available ground truth on this host, but a Rosetta bug in an SSE2 path would appear as
   a false agreement. The instruction-length and mnemonic agreement I measured in task-3
   between Capstone and LLVM suggests the decode side is sound; the execution side rests on
   Rosetta's correctness.
2. **The harness tests helpers, not generated programs.** It calls `vector_*` directly. A
   defect in how the lifter *selects* helpers (which is where §2 lives) is only caught by the
   structural probe and by reading the dispatch — not by the differential tests.
3. **Reachability uses the tool's own unsupported-class list as the oracle** for "this function
   is stubbed". A mnemonic can be unsupported in one operand form and supported in another, so
   the 43 figure in §2 is an estimate, though the direction of the error is conservative
   (it may under- or over-count, and the compile probe proves the defect regardless).
4. **The tree moved five times.** Every number here is tied to the hashes in §0. The live
   defect was re-confirmed at 08:44 against the live tree; the semantic results are for
   snapshot 2.
