# Backward flag liveness for Recomp Studio — implementable spec

**Task:** task-7. **Write scope:** this file only. **Derived from:** `reports/sr-analysis.md` §8 item 1.
**SR source analysed:** `research/upstream/SR` at `ac690ddf3010bc3d2c875cb1b5e8da4f53a8d5b3`.
**Recomp Studio source read:** `core/discovery/function_discovery.{hpp,cpp}`,
`core/semantics/x86_64_lifter.{hpp,cpp}`, `runtime/recomp_runtime.{hpp,cpp}`,
`core/verification/differential_harness.{hpp,cpp}`, `core/harness/repair_harness.cpp`,
`tests/end-to-end/recompile_test.py`, `tests/fixtures/apps/*`.

Every SR claim below was re-verified with `sed -n`/`grep -n` against the checkout before writing.
Anything I did not read is marked **not verified**. Recomp Studio claims are cited to the file I read.

> **Concurrency caveat.** `core/` and `runtime/` are being edited by other agents while this spec is
> written. The Recomp Studio line numbers below were re-verified against these content hashes
> (sha256, first 16 hex chars) and may drift:
>
> | File | sha256 prefix |
> |---|---|
> | `core/semantics/x86_64_lifter.cpp` | `f660bf0e966d7b7f` |
> | `runtime/recomp_runtime.hpp` | `726e3e07757aedb0` |
> | `runtime/recomp_runtime.cpp` | `b0d2aec3d5976a2e` |
> | `core/discovery/function_discovery.cpp` | `87229bfd832f8f8a` |
> | `core/discovery/function_discovery.hpp` | `fc2f1e84b277956f` |
> | `core/verification/differential_harness.hpp` | `55fd823c697242d4` |
> | `core/harness/repair_harness.cpp` | `624a1a677755f51e` |
> | `core/harness/repair_harness.hpp` | `800f6f3ad18d24f1` |
>
> Where a line number and a quoted code fragment disagree, **trust the fragment** — locate it by
> symbol. `x86_64_lifter.cpp` gained a `ret` handler between two of my passes, which moved
> `lahf`/`sahf` and `cld`/`std`; the numbers below are the post-move ones.

---

## 0. The one-sentence version

SR computes, for each basic-block-sized region, the set of flags that are **live-out of every
instruction**, by walking the region **backwards** from its end, and emits only the flag
computations in that set; if the live set does not close to empty at the region's entry it
**aborts the whole recompilation** rather than guessing
(`SRW/SR_full_llasm.c:35,45,203,248-255,271-312`).

For Recomp Studio the equivalent win is: `add`/`sub`/`inc`/`dec`/`and`/`or`/`xor`/`shl` currently
call helpers that materialise six flag fields unconditionally
(`runtime/recomp_runtime.hpp:129-150,160-185,220-262`), even when the following instruction reads
only ZF. The change is to pass a **`FlagMask wanted`** to the emitter and guard each field write on
it. Because the mask is a literal at every call site and the helpers are `inline` in the generated
project, clang++ constant-folds the guards away and the arithmetic survives while the flag
computation disappears.

**Step 1 (§4.1) is trivially sound and needs no control-flow analysis.** **Step 2 (§4.2) is the SR
technique and needs a block graph.** Both are specified; ship Step 1 first.

---

## 1. What SR actually does, verified

### 1.1 The flag vocabulary

`SRW/udis86_dep.h:39-70` — a single `uint_fast32_t` bitmask vocabulary:

| Bit | Value | Name | SR line |
|---|---|---|---|
| CF | `0x01` | `FL_CARRY` | `SRW/udis86_dep.h:44` |
| PF | `0x02` | `FL_PARITY` | `:45` |
| AF | `0x04` | `FL_ADJUST` | `:46` |
| ZF | `0x08` | `FL_ZERO` | `:47` |
| SF | `0x10` | `FL_SIGN` | `:48` |
| OF | `0x20` | `FL_OVERFLOW` | `:49` |
| DF | `0x40` | `FL_DIRECTION` | `:50` |
| IF | `0x80` | `FL_INTERRUPT` | `:51` |
| (TF) | `0x0100` | `FL_TASK` | `:52` |

Composite sets, `SRW/udis86_dep.h:54-58`:

```c
FL_AH       = FL_CARRY | FL_PARITY | FL_ADJUST | FL_ZERO | FL_SIGN,   // :54
FL_COND_SUB = FL_CARRY | FL_PARITY | FL_ADJUST | FL_ZERO | FL_SIGN | FL_OVERFLOW,  // :55
FL_COND     = FL_CARRY | FL_PARITY | FL_ADJUST | FL_ZERO | FL_SIGN | FL_OVERFLOW,  // :56
FL_COND_ALL = FL_CARRY | FL_PARITY | FL_ADJUST | FL_ZERO | FL_SIGN | FL_OVERFLOW,  // :57
FL_ALL      = FL_COND | FL_DIRECTION | FL_INTERRUPT | FL_TASK,        // :58
```

Escape hatches, `SRW/udis86_dep.h:60-69`:

```c
FL_INST_Z = 0x00010000, FL_INST_S = 0x00020000, FL_INST_B = 0x00030000,
FL_INST_A = 0x00040000, FL_INST_L = 0x00050000, FL_INST_G = 0x00060000,
FL_INST_MASK = 0x00070000,     // :66  "the instruction's own condition code"
FL_WEAK     = 0x10000000,      // :68
FL_SPECIFIC = 0x80000000       // :69
```

Two flat arrays hold the summary, `SRW/udis86_dep.h:72-73`, populated by `init_udis86_dep()`.
Every entry defaults to `FL_UNKNOWN` (`SRW/udis86_dep.c:39-43`) and is overwritten by an explicit
`SET_FLAGS(mnemonic, reads, writes)` (`SRW/udis86_dep.c:29-32`).

### 1.2 The backward pass

`SRW/SR_full_llasm.c:32-316` is the whole algorithm, one region at a time:

```
 35:  uint_fast32_t cur_ofs, flags_to_write, flags_write, flags_read;
 43:  cur_ofs = region->end_ofs;
 45:  flags_to_write = 0;                       // <-- empty live-out seed
 88:  output = section_output_list_FindEntryEqual(Entry, cur_ofs);
 89:  while (!finished) {
127:      ud_set_input_buffer(...); ud_set_pc(...);
130:      ret = ud_disassemble(&ud_obj);
133:      if (ret == 0 || ret != output->len + 1) { ...error... }
141:      flags_read  = flags_needed[ud_obj.mnemonic];
142:      flags_write = flags_modified[ud_obj.mnemonic];
143:      if (flags_read == FL_UNKNOWN || flags_write == FL_UNKNOWN) { ...error... }
151:      iflags = section_iflags_list_FindEntryEqual(Entry, cur_ofs);
152:      if (iflags) { ... flags_to_write |= iflags->begin; }
203:      ret = SR_disassemble_llasm_instruction(Entry, output, flags_to_write,
                                               &flags_write, &flags_read, &last_instruction);
224:      if (flags_read == FL_SPECIFIC || flags_write == FL_SPECIFIC) { ...error... }
241:      if ((flags_to_write & FL_INST_MASK) && (flags_read || (flags_write & ~FL_INST_MASK))) { ...error... }
248:      flags_to_write &= ~flags_write;                       // this instr defined them
249:      if (flags_to_write == FL_WEAK) flags_to_write = FL_NONE;
250:      flags_to_write |= flags_read;                         // live-in from here down
252:      if (iflags) { flags_to_write &= ~((uint32_t) iflags->end); }
260:      if (cur_ofs == region->begin_ofs) finished = 1;
266:      else { cur_ofs--; output = section_output_list_FindEntryEqualOrLower(Entry, cur_ofs); }
271:  if (flags_to_write) { ...error... }
```

The three load-bearing lines are **203** (the generator receives `flags_to_write`, i.e. the flags
that are live *after* this instruction and therefore must actually be produced), **248-250** (the
live-set update), and **271-312** (the closure check).

### 1.3 The instruction handler may refine the static summary

`flags_write` and `flags_read` are passed **by pointer** (`SRW/SR_full_llasm_instr.c:1620`), read
back at `:1636-1637`, and written back at `:7814-7815`. This is how operand shape refines the
mnemonic-level default — `SRW/SR_full_llasm_instr.c:4233-4246`:

```c
if (ud_obj.mnemonic == UD_Imov &&
    ud_obj.operand[0].type == UD_OP_REG && ud_obj.operand[1].type == UD_OP_REG &&
    ((ud_obj.operand[0].base >= UD_R_CR0 && ud_obj.operand[0].base <= UD_R_DR15) ||
     (ud_obj.operand[1].base >= UD_R_CR0 && ud_obj.operand[1].base <= UD_R_DR15)))
{
    flags_write = FL_COND;      /* flags undefined */
}
else
{
    flags_write = FL_NONE;      /* no flags affected */
}
```

This is why `SET_FLAGS(UD_Imov, FL_NONE, FL_SPECIFIC)` at `SRW/udis86_dep.c:177` — `FL_SPECIFIC` is
the sentinel meaning "the handler decides", and it is a hard error if it survives to `:224-230`.

### 1.4 The shift-count hazard, and how SR handles it

`shl`/`shr`/`sar` with a count of 0 **leave the flags unchanged** on real x86. SR's table says
`SET_FLAGS(UD_Ishl, FL_NONE, FL_COND)` (`SRW/udis86_dep.c:235`) — i.e. "writes all condition flags",
which would be wrong for count 0. SR fixes it in the handler:

* **Immediate count**, `SRW/SR_full_llasm_instr.c:6009-6016`:
  ```c
  if (value == 0) { flags_write = 0; }
  else            { SR_llasm_helper_sal_32(...); }
  ```
  A count of 0 is statically known, so the instruction is correctly modelled as writing **nothing**.
* **Register count** (`cl`), `SRW/SR_full_llasm_instr.c:5981-5984`:
  ```c
  if (flags_to_write)
  {
      fprintf(stderr, "Error: flags not calculated - %i - %i - %s\n", ...);
  }
  ```
  **Hard error if any flag is live.** SR refuses to guess.

Our helpers have the identical early-out (`runtime/recomp_runtime.hpp:224-225` in `shift_left`,
`:240-241` in `shift_right_logical`, `:250-251` in `shift_right_arithmetic`, `:300-301` in
`rotate_left`, `:313-314` in `rotate_right`), so we inherit the same hazard and must adopt the same
rule. See §5.4.

### 1.5 Regions are basic blocks

`SR_disassemble_create_regions` (`SRW/SR_full.c:341-388`) builds regions from a bound list, and the
bound list is populated at control-transfer instructions:

| Instruction | Bound | SR line |
|---|---|---|
| `call` | `end` at instr, `begin` at next | `SRW/SR_full_win32.c:365-366`, `:550-551` |
| `ret` | `end` at instr | `SRW/SR_full_win32.c:576` |
| `retf` | `end` at instr | `SRW/SR_full_win32.c:962-963` |
| `iret` | `end` at instr | `SRW/SR_full_win32.c:560` |
| `jmp` | `end` at instr | `SRW/SR_full_win32.c:689-690` |
| **`jcc` (16 forms)** | `end` at instr, `begin` at next | `SRW/SR_full_win32.c:619-627` |
| `jcxz`/`jecxz`/`jrcxz` | `end` at instr, `begin` at next | `SRW/SR_full_win32.c:619-627` |
| `loop`/`loope`/`loopne` | `end` at instr, `begin` at next | `SRW/SR_full_win32.c:845-847` |

So **SR's regions are basic blocks**, and because the empty live-out seed at
`SRW/SR_full_llasm.c:45` assumes nothing is live out of the region, SR's soundness rests entirely on
the closure check at `:271-312`: a flag that is live at a region's *entry* means it was produced in a
different region, which SR cannot reason about, so it errors.

### 1.6 The one cross-region flow SR does handle

`jcc` followed by `setcc` of the same condition puts a flag read in the *next* region. SR stitches
the two regions together with the `iflags` list — `SR_disassemble_change_cjump_iflags`
(`SRW/SR_full_win32.c:204-250`), called for the `jcc` at `:610-616` and for the `setcc` at
`:1128-1135`. It writes `iflags->begin = flags_needed[setcc]` at the `jcc`'s offset (`:233-236`) and
`iflags->end = flags_needed[setcc]` at the `setcc`'s offset (`:211-215`), which the pass consumes at
`SRW/SR_full_llasm.c:161` and `:252-255`. Net effect: the flag is kept live from the `setcc`
backwards through the `jcc` to its producer, while each region's own live set still closes to empty.

**This is a hand-written special case for one pattern.** It is the price of block-local analysis
with an empty seed. §4.2 removes the need for it by doing real cross-block dataflow.

---

## 2. Why SR's shape does not port directly

Two structural differences matter, and both must be handled explicitly.

### 2.1 Recomp Studio's "blocks" are not basic blocks

`block_starts` is filled by `FunctionDiscovery::discover()`
(`core/discovery/function_discovery.cpp`):

* the function entry — `:142`
* the **target** of every conditional branch — `:172`
* the **target** of every `jmp` that is not a known function entry — `:184` (else it becomes a
  tail-call target, `:182`)

Note what is *absent*: **the fall-through instruction after a conditional branch is not inserted**
(`:169-177` inserts only `*target`, then `address = next_address; continue;`). So a run delimited by
consecutive `block_starts` can contain a conditional branch **in the middle**:

```
0x100:  cmp eax, ebx
0x102:  jz 0x200          ; target 0x200 becomes a block start; fall-through continues linearly
0x104:  mov ecx, 1
0x107:  jmp 0x200
0x200:  ...               ; next block start
```
Here `block_starts = {0x100, 0x200}` and the run `[0x100, 0x107]` has **one entry but two exits**.
That is not a basic block, and SR's "empty live-out seed" reasoning does not hold for it: a flag
written at `0x100` and read at `0x200` would be dropped, because `0x200` is outside the run and the
run's own terminator (`0x107 jmp`) reads nothing.

### 2.2 There is no CFG, and indirect branches are unanalysed

`RecoveredFunction` (`core/discovery/function_discovery.hpp:40-45`) carries only
`instructions`, `block_starts` and `tail_call_targets`. There are no successor edges, and
`direct_branch_target` (`core/discovery/function_discovery.cpp:89-94`) is private and only handles
immediate operands — an indirect `jmp`/`call` target is never recovered.

**Consequence:** for any block reachable by an indirect jump, the entry live set is unbounded.

### 2.3 What this means

**A direct port of SR's region-local pass to Recomp Studio is unsound.** §4.2 gives the corrected
version, and §5 gives the disqualification rules that make it fail closed.

---

## 3. Data model additions

### 3.1 A flag mask type

```cpp
// core/semantics/flag_liveness.hpp  (new)
#pragma once
#include <cstdint>
#include <string>

namespace recomp::semantics {

// One bit per architectural flag. Values deliberately match SR's
// vocabulary (SRW/udis86_dep.h:44-52) so the transcribed table in §5
// reads one-for-one against its source.
enum FlagMask : std::uint32_t {
  kFlagNone      = 0u,
  kFlagCarry     = 1u << 0,   // CF  -- SRW/udis86_dep.h:44
  kFlagParity    = 1u << 1,   // PF  -- SRW/udis86_dep.h:45
  kFlagAuxiliary = 1u << 2,   // AF  -- SRW/udis86_dep.h:46
  kFlagZero      = 1u << 3,   // ZF  -- SRW/udis86_dep.h:47
  kFlagSign      = 1u << 4,   // SF  -- SRW/udis86_dep.h:48
  kFlagOverflow  = 1u << 5,   // OF  -- SRW/udis86_dep.h:49
  kFlagDirection = 1u << 6,   // DF  -- SRW/udis86_dep.h:50
  // SRW/udis86_dep.h:55-57
  kFlagsArithmetic = kFlagCarry | kFlagParity | kFlagAuxiliary |
                     kFlagZero | kFlagSign | kFlagOverflow,
  kFlagsCondition  = kFlagsArithmetic,
  kFlagLahf        = kFlagCarry | kFlagParity | kFlagAuxiliary | kFlagZero | kFlagSign,  // :54
};

inline constexpr std::uint32_t operator|(FlagMask a, FlagMask b) {
  return static_cast<std::uint32_t>(a) | static_cast<std::uint32_t>(b);
}

}  // namespace recomp::semantics
```

`kFlagsArithmetic` corresponds to SR's `FL_COND` (`SRW/udis86_dep.h:56`); `kFlagLahf` to `FL_AH`
(`:54`).

### 3.2 A per-instruction summary

```cpp
struct FlagSummary {
  std::uint32_t reads{kFlagNone};   // flags this instruction consumes as inputs
  std::uint32_t writes{kFlagNone};  // flags this instruction may modify
  bool unknown{false};              // no table entry / unresolved operand shape
  std::string reason;               // diagnostic text when unknown
};
```

`unknown == true` is the Recomp Studio spelling of SR's `FL_UNKNOWN` / surviving `FL_SPECIFIC`
(`SRW/udis86_dep.c:39-43`, `SRW/SR_full_llasm.c:143-149,224-230`) and must be a **hard error for the
whole function**, not a per-instruction fallback. See §5.

### 3.3 The liveness result

```cpp
struct FunctionFlagLiveness {
  bool analysed{false};                  // false => keep eager flags
  std::string fallback_reason;           // why we bailed, for the diagnostic
  std::map<std::uint64_t, std::uint32_t> live_out;  // address -> flags live AFTER this instr
};
```

`live_out[addr]` is exactly SR's `flags_to_write` at the moment the generator is called
(`SRW/SR_full_llasm.c:203`). `analysed == false` means "emit today's code unchanged".

---

## 4. The algorithm

### 4.0 Where it plugs in

Today `X86_64Lifter::emit_instruction` (`core/semantics/x86_64_lifter.cpp:328-334`) builds each
statement from a `const DecodedInstruction&` and appends to `output`. Add one parameter:

```cpp
void emit_instruction(const discovery::DecodedInstruction& instruction,
                      const discovery::RecoveredFunction& function,
                      std::uint32_t flags_wanted,        // NEW
                      std::string& output) const;
```

and thread it through `lift_function` (`core/semantics/x86_64_lifter.cpp:1189-1199`), which is where
the per-function liveness map is computed once and looked up per instruction. **Keeping
`flags_wanted` a parameter means the tier in §4.1 and the tier in §4.2 are drop-in replacements for
each other** — only the computation of the map changes.

### 4.1 Step 1 — function-wide read set (trivially sound, no CFG, ~1 hour)

This is the SR idea reduced to the one part that needs no reachability reasoning.

```
R_all := union over all instructions I in function.instructions of summary(I).reads

for each instruction I:
    live_out[I.address] := R_all              // constant for the whole function
    flags_wanted := live_out[I.address] & summary(I).writes
    emit I with only flags_wanted materialised
```

**Soundness argument.** A write to flag F is elided only when **no instruction anywhere in the
function reads F**. There is no reachability question to get wrong, no CFG, no assumption about
block shape, and no interaction with indirect branches. The elided value can never be observed,
because nothing in the translation unit reads it.

**Why it is worth shipping first.** In practice a function's flag reads are dominated by its branch
conditions, and most branches test one flag. A function whose only conditional jumps are `jz`/`jnz`
has `R_all = {ZF}`, so `add`/`sub`/`and`/`or`/`xor` immediately stop computing CF/PF/AF/SF/OF — five
of six flag computations gone with zero analysis risk.

**Honest limitation.** It cannot eliminate a write that is merely *overwritten before use* — e.g.
`add eax, ebx; cmp ecx, edx; jz L` still computes ZF for the `add` because `jz` reads ZF. That is
what Step 2 is for.

### 4.2 Step 2 — the SR backward pass, made sound for our block shape (~1 day)

#### 4.2.1 Build the block graph

```
blocks := address-ordered partition of function.instructions at every block_starts address,
          plus the function entry (function.entry).
          Block B_i = [start_i, end_i] where end_i is the instruction immediately before start_{i+1}.

for each block B:
    succ(B) := {}
    for each instruction I in B:
        if I is a conditional branch or jmp with a direct target T:
            if T is a block start in B's function:      succ(B) += block_at(T)
            else:                                       DISQUALIFY(see §5.2 D3)
        if I is jmp with an indirect operand:           DISQUALIFY(§5.2 D1)
    if B's last instruction is not a terminator:        succ(B) += B_{i+1}   (fall-through)
```

#### 4.2.2 Backward dataflow to fixpoint

Standard backward may-analysis over the block graph. Iterate until no live set changes (loops
guarantee at least two passes):

```
for each block B:  live_in(B) := 0 ; live_out(B) := 0

repeat until fixpoint:
    for each block B in any order:
        out := union over S in succ(B) of live_in(S)
        live_out(B) := out
        // transfer: walk B's instructions backwards, exactly as SRW/SR_full_llasm.c:260-268
        live := out
        for I in reverse address order within B:
            per_instruction_live_out[I.address] := live
            live := (live & ~summary(I).writes) | summary(I).reads
        live_in(B) := live
```

The inner loop is **SR's loop verbatim** — `SRW/SR_full_llasm.c:248-250` is
`flags_to_write &= ~flags_write; flags_to_write |= flags_read;`, and `SRW/SR_full_llasm.c:260-268`
is the reverse-address step.

`per_instruction_live_out[I.address]` is what the emitter receives as `flags_wanted`. The emitter
then materialises `flags_wanted & summary(I).writes` — never more.

#### 4.2.3 Why the fixpoint is necessary and SR's empty seed is not enough

SR seeds `flags_to_write = 0` at the region end (`SRW/SR_full_llasm.c:45`) and compensates with the
closure check. In our block shape (§2.1) a run can have an exit in the middle, so an empty seed is
unsound. The fixpoint propagates each successor's `live_in` back to the predecessor's exits, which
is the general form of what SR's `iflags` hack does for one pattern (§1.6).

#### 4.2.4 The closure requirement, restated for us

SR errors when a region's live set does not close to empty at its entry
(`SRW/SR_full_llasm.c:271-312`). In the fixpoint formulation that condition becomes: **a flag may be
live-in to a block** (it is produced by an earlier block and consumed later), which is fine *provided
every predecessor is in the graph*. That is precisely what §5.2's disqualification rules protect.

---

## 5. The per-mnemonic flag table

### 5.1 How to read this

* **Reads** = flags the instruction consumes as inputs (must be live before it).
* **Writes** = flags the instruction may modify (kills liveness of the previous value).
* **SR source** = the `SET_FLAGS` line I transcribed it from, in `SRW/udis86_dep.c`.
* **SR's set is a conservative over-approximation** where noted. Over-approximating writes is safe
  (it kills liveness more aggressively than reality — see §7.1 for why that direction is the
  dangerous one anyway).
* Where SR has **no entry**, the row is marked `derived` — taken from the Intel SDM and from the
  behaviour of the Recomp Studio helper the lifter actually calls. Those rows are **not** SR-sourced
  and must be reviewed by hand.
* `FL_COND` / `FL_COND_SUB` both expand to `CF|PF|AF|ZF|SF|OF` (`SRW/udis86_dep.h:55-56`).

### 5.2 Integer ALU

| Mnemonic | Reads | Writes | SR source | Notes |
|---|---|---|---|---|
| `add` | — | `CF PF AF ZF SF OF` | `udis86_dep.c:47` `FL_NONE, FL_COND` | exact |
| `sub` | — | `CF PF AF ZF SF OF` | `udis86_dep.c:245` `FL_NONE, FL_COND_SUB` | exact |
| `adc` | `CF` | `CF PF AF ZF SF OF` | `udis86_dep.c:46` `FL_CARRY, FL_COND` | exact; matches `add_with_carry` reading `context->carry_flag` (`runtime/recomp_runtime.hpp:151-153`) |
| `sbb` | `CF` | `CF PF AF ZF SF OF` | `udis86_dep.c:218` `FL_CARRY, FL_COND_SUB` | exact; `subtract_with_borrow` reads carry (`runtime/recomp_runtime.hpp:155-158`) |
| `and` | — | `CF PF AF ZF SF OF` | `udis86_dep.c:48` `FL_NONE, FL_COND` | over-approx: real `and` clears CF/OF and leaves AF undefined |
| `or` | — | `CF PF AF ZF SF OF` | `udis86_dep.c:191` `FL_NONE, FL_COND` | over-approx, same |
| `xor` | — | `CF PF AF ZF SF OF` | `udis86_dep.c:259` `FL_NONE, FL_COND` | over-approx, same |
| `test` | — | `CF PF AF ZF SF OF` | `udis86_dep.c:248` `FL_NONE, FL_COND` | over-approx, same |
| `cmp` | — | `CF PF AF ZF SF OF` | `udis86_dep.c:64` `FL_NONE, FL_COND_SUB` | exact |
| `not` | — | — | `udis86_dep.c:188` `FL_NONE, FL_NONE` | exact |
| `inc` | — | `PF AF ZF SF OF` (not CF) | `udis86_dep.c:130` | exact; matches `increment_with_flags` saving/restoring CF (`runtime/recomp_runtime.hpp:191-196`) |
| `dec` | — | `PF AF ZF SF OF` (not CF) | `udis86_dep.c:70` | exact; `decrement_with_flags` (`runtime/recomp_runtime.hpp:198-203`) |
| `neg` | — | `CF PF AF ZF SF OF` | `udis86_dep.c:186` `FL_NONE, FL_COND_SUB` | exact |
| `xchg` | — | — | `udis86_dep.c:257` `FL_NONE, FL_NONE` | exact |
| `xlatb` | — | — | `udis86_dep.c:258` | exact |
| `bswap` | — | — | `udis86_dep.c:52` | exact |

### 5.3 Multiply / divide — **read this before transcribing; SR is wrong for us here**

**The governing rule for this section: the table must match the helper the lifter actually calls,
not the Intel SDM and not SR.** Our helpers define flag values that the SDM calls *undefined*, and
the differential harness compares against Unicorn, which also produces a specific value. A table that
follows the SDM instead of the helper will elide a write that Unicorn's value depends on.

| Mnemonic | Reads | Writes | SR source | Our helper (verified) |
|---|---|---|---|---|
| `imul` (1-operand) | — | `CF PF AF ZF SF OF` | `udis86_dep.c:128` `FL_NONE, FL_COND` — **matches our helper** | `signed_multiply_single` (`runtime/recomp_runtime.cpp:492-511`) writes CF/OF (`:498,:508`), zeroes AF (`:499,:509`), and calls `update_zero_sign_parity` (`:501,:510`) → all six |
| `imul` (2/3-operand) | — | `CF PF AF ZF SF OF` | same | `signed_multiply_two` (`runtime/recomp_runtime.cpp:513-531`), same pattern → all six |
| `mul` | — | `CF PF AF ZF SF OF` | `udis86_dep.c:183` `FL_NONE, FL_COND` — **matches our helper** | `unsigned_multiply_single` (`runtime/recomp_runtime.cpp:533-543`), same pattern → all six |
| `div` | — | **none** | `udis86_dep.c:71` says `FL_NONE, FL_COND` — **WRONG for us; do not copy it** | `unsigned_divide` (`runtime/recomp_runtime.cpp:545-557`) **writes no flags at all** |
| `idiv` | — | **none** | `udis86_dep.c:127` says `FL_NONE, FL_COND` — **WRONG for us; do not copy it** | `signed_divide` (`runtime/recomp_runtime.cpp:559-574`) **writes no flags at all** |

**The `div`/`idiv` row is the single most dangerous transcription in this document.** SR models them
as writing `FL_COND`, which would tell the liveness pass that `div` kills CF — so the pass would
elide whatever produced CF before the `div`. Our helper leaves CF untouched, so a later `adc` would
then read a stale CF, while the current eager code reads the correct pass-through value. Copying SR
verbatim here is a silent miscompile. **Use `reads = writes = 0` for `div`/`idiv`.**

SR's handler comment at `SRW/SR_full_llasm_instr.c:3240` (`/* SF,ZF,AF,PF undefined, CF,OF -
modified */`) shows SR's own handler is narrower than its table; `SRW/SR_full_llasm_instr.c:3248`
shows the emission guarded on liveness:
```c
if (flags_to_write & (FL_CARRY | FL_OVERFLOW)) { SR_disassemble_change_flags(...); ... }
```

### 5.4 Shifts and rotates — read §1.4 before implementing

| Mnemonic | Reads | Writes | SR source | Notes |
|---|---|---|---|---|
| `shl` / `sal` | — | `CF PF ZF SF OF` (AF undefined) | `udis86_dep.c:235` `FL_NONE, FL_COND` | over-approx (SR includes AF). Handler comment `SRW/SR_full_llasm_instr.c:5973`: `/* SF,ZF,PF,CF - modified, AF - undefined, OF - modified for 1-bit shifts, else undefined */` |
| `shr` | — | `CF PF ZF SF OF` | `udis86_dep.c:237` | same comment |
| `sar` | — | `CF PF ZF SF OF` | `udis86_dep.c:217` | same comment |
| `rol` | — | `CF OF` | `udis86_dep.c:211` `FL_NONE, FL_CARRY\|FL_OVERFLOW` | **our `rotate_left` also zeroes `auxiliary_flag` (`runtime/recomp_runtime.hpp:305`), so use `CF OF AF`** |
| `ror` | — | `CF OF` | `udis86_dep.c:212` | our `rotate_right` also zeroes AF (`runtime/recomp_runtime.hpp:319`) → `CF OF AF` |
| `rcl` | `CF` | `CF OF` | `udis86_dep.c:209` `FL_CARRY, FL_CARRY\|FL_OVERFLOW` | exact; `rotate_left_through_carry` reads `context->carry_flag` (`runtime/recomp_runtime.hpp:329`) |
| `rcr` | `CF` | `CF OF` | `udis86_dep.c:210` | `rotate_right_through_carry` reads CF (`runtime/recomp_runtime.hpp:339-345`) |
| `shld` | — | `CF PF ZF SF OF` | `udis86_dep.c:236` `FL_NONE, FL_COND` | over-approx; handler zeroes AF |
| `shrd` | — | `CF PF ZF SF OF` | `udis86_dep.c:238` | over-approx |

**The count==0 rule (§1.4) must be applied to all ten.** Our helpers early-return on
`count % bits == 0` without touching flags (`runtime/recomp_runtime.hpp:224-225,240-241,250-251,
300-301,313-314`). Two cases:

* **Immediate count, statically 0 modulo the operand width** → `writes = 0`, `reads = 0`.
  This is SR's `SRW/SR_full_llasm_instr.c:6009-6016`.
* **Immediate count, nonzero modulo width** → the table above applies.
* **Register count (`cl`)** → the count is unknown. Treat the instruction as
  **`reads |= writes |= CF OF ZF SF PF`** — i.e. it may preserve or clobber, so nothing upstream may
  be elided and nothing downstream may assume a fresh value. This is strictly safer than SR's
  hard error (`SRW/SR_full_llasm_instr.c:5981-5984`) and costs nothing at runtime, because the
  emitted helper already implements the conditional write correctly. **If the implementer prefers to
  mirror SR exactly, make it a whole-function fallback instead (§6.2 D5).**

### 5.5 Bit test, bit scan

| Mnemonic | Reads | Writes | SR source | Notes |
|---|---|---|---|---|
| `bt` | — | `CF` | `udis86_dep.c:53` `FL_NONE, FL_COND` | **SR over-approximates**: Intel defines only CF for `bt`; SF/ZF/AF/PF are undefined, OF is undefined for the register form. Our lifter writes only `context->carry_flag` (`core/semantics/x86_64_lifter.cpp:526`). Use `CF`. |
| `bts` | — | `CF` | `udis86_dep.c:54` | same |
| `btr` | — | `CF` | **no SR entry** — `derived` | SR's table omits `btr`; it would be `FL_UNKNOWN` and abort (`SRW/SR_full_llasm.c:143-149`). Our lifter handles it (`x86_64_lifter.cpp:518-539`). |
| `btc` | — | `CF` | **no SR entry** — `derived` | as `btr` |
| `bsf` | — | `ZF` | **no SR entry** — `derived` | SR has only `bsr` (`udis86_dep.c:51`). Our `bit_scan_forward` writes `context->zero_flag` only (`runtime/recomp_runtime.hpp:551-560`). |
| `bsr` | — | `ZF` | `udis86_dep.c:51` `FL_NONE, FL_COND` | SR over-approximates; our `bit_scan_reverse` writes `context->zero_flag` only (`runtime/recomp_runtime.hpp:542-549`). Use `ZF`. |

### 5.6 Atomic / exchange

| Mnemonic | Reads | Writes | SR source | Notes |
|---|---|---|---|---|
| `xadd` | — | `CF PF AF ZF SF OF` | **no SR entry** — `derived` | SR's table has no `xadd`. Our lifter emits `add_with_flags` (`core/semantics/x86_64_lifter.cpp:942-946`), so the summary is `add`'s. |
| `cmpxchg` | — | `CF PF AF ZF SF OF` | **no SR entry** — `derived` | Our lifter emits `compare_with_flags` then **reads `context->zero_flag` in the same instruction** (`core/semantics/x86_64_lifter.cpp:948-952`). See §9.3 — this is an intra-instruction read and the summary must reflect it, or the emitted code will read a value it just decided was dead. |

### 5.7 `lahf` / `sahf` / `pushfd` / `popfd` / `pushfw`

| Mnemonic | Reads | Writes | SR source | Notes |
|---|---|---|---|---|
| `lahf` | `CF PF AF ZF SF` | — | `udis86_dep.c:160` `FL_AH \| FL_WEAK, FL_NONE` | SR marks the read **`FL_WEAK`** — see §6.1. Our lifter reads all five fields directly (`core/semantics/x86_64_lifter.cpp:690-694`). |
| `sahf` | — | `CF PF AF ZF SF` | `udis86_dep.c:215` `FL_NONE, FL_AH` | exact; our lifter writes exactly those five (`x86_64_lifter.cpp:696-700`) |
| `pushfd` / `pushfw` / `pushfq` | `CF PF AF ZF SF OF DF IF` | — | `udis86_dep.c:203-204` `FL_ALL \| FL_WEAK, FL_NONE` | **Our lifter does not implement `pushfd`/`popfd` at all** — no `mnemonic == "pushf..."` branch exists in `core/semantics/x86_64_lifter.cpp` (grep for `pushf` returns nothing). Not verified whether a fixture needs it. |
| `popfd` / `popfw` / `popfq` | — | `CF PF AF ZF SF OF DF IF` | `udis86_dep.c:199` `FL_NONE, FL_ALL` | as above |
| `stc` | — | `CF` | `udis86_dep.c:239` | exact |
| `cmc` | `CF` | `CF` | `udis86_dep.c:63` `FL_CARRY, FL_CARRY` | exact |
| `cld` / `std` | — | `DF` | `udis86_dep.c:61,240` | our lifter sets `context->direction_flag` (`x86_64_lifter.cpp:822-823`) |

### 5.8 Conditionals — `jcc`, `setcc`, `cmovcc`

All are **pure readers**; none writes flags.

| Mnemonic | Reads | SR source |
|---|---|---|
| `jo` / `jno` | `OF` | **no SR entry** — `derived`. SR's list starts at `UD_Ija` (`udis86_dep.c:136`); `jo`/`jno` are missing and would be `FL_UNKNOWN`. |
| `jb` / `jae` | `CF` | `udis86_dep.c:138,137` |
| `jz` / `je` | `ZF` | `udis86_dep.c:157` |
| `jnz` / `jne` | `ZF` | `udis86_dep.c:155` |
| `jbe` | `ZF CF` | `udis86_dep.c:139` |
| `ja` | `ZF CF` | `udis86_dep.c:136` |
| `js` / `jns` | `SF` | `udis86_dep.c:156,154` |
| `jp` / `jnp` | `PF` | `udis86_dep.c:152,153` |
| `jl` / `jge` | `SF OF` | `udis86_dep.c:145,143` |
| `jle` / `jg` | `ZF SF OF` | `udis86_dep.c:146,142` |
| `jecxz` / `jrcxz` | — | `udis86_dep.c:141` `FL_NONE, FL_NONE` |
| `loop` | — | `udis86_dep.c:171` |
| `loope` | `ZF` | `udis86_dep.c:172` `FL_ZERO, FL_NONE` |
| `loopne` | `ZF` | **commented out** at `udis86_dep.c:173`; `derived` |
| `seto` / `setno` | `OF` | **no SR entry** — `derived`. SR's setcc list (`udis86_dep.c:220-234`) omits the overflow forms. |
| `setb`/`setnae`/`setc` | `CF` | `udis86_dep.c:221` |
| `setae`/`setnb`/`setnc` | `CF` | `udis86_dep.c:227` (commented) — `derived` |
| `setz`/`sete` | `ZF` | `udis86_dep.c:234` |
| `setnz`/`setne` | `ZF` | `udis86_dep.c:232` |
| `setbe`/`setna` | `ZF CF` | `udis86_dep.c:222` |
| `seta`/`setnbe` | `ZF CF` | `udis86_dep.c:220` |
| `sets`/`setns` | `SF` | `udis86_dep.c:233,231` |
| `setp`/`setpe` | `PF` | **no SR entry** — `derived` |
| `setnp`/`setpo` | `PF` | **no SR entry** — `derived` |
| `setl`/`setnge` | `SF OF` | `udis86_dep.c:225` |
| `setge`/`setnl` | `SF OF` | `udis86_dep.c:224` |
| `setle`/`setng` | `ZF SF OF` | `udis86_dep.c:226` |
| `setg`/`setnle` | `ZF SF OF` | `udis86_dep.c:223` |
| `cmovcc` (all 16) | same as the matching `jcc` | **no SR entry at all** — `derived` |

The condition-code → flag mapping is already encoded once in Recomp Studio, in
`evaluate_condition` (`runtime/recomp_runtime.hpp:361-380`); the table above is that same mapping
read backwards, and the two must be kept consistent. The mnemonic spellings are already normalised
by `condition_codes()` (`core/semantics/x86_64_lifter.cpp:51-69`), and the `setcc`/`cmovcc`/`jcc`
dispatch sites are `:736-746` and `:789-790`.

### 5.9 Everything else the lifter implements

`mov`, `movabs`, `movzx`, `movsx`, `movsxd`, `lea`, `push`, `pop`, `call`, `ret`, `retf`, `jmp`,
`nop`/`endbr32`/`endbr64`/`pause`, `cpuid`, `hlt`, `int3`, `ud0`/`ud1`/`ud2`, the string operations,
all x87 (`f*`), all SIMD/VEX, `prefetch*`, `fwait`/`wait` → **reads = writes = 0**.

SR agrees for the ones it lists: `mov` `udis86_dep.c:177` (but see §5.10), `lea` `:163`, `push`
`:200`, `pop` `:196`, `call` `:57`, `ret` `:207`, `retf` `:208`, `jmp` `:144`, `nop` `:187`, string ops
`:168-170,178-180,193,242-244`, all x87 `:77-124`, `wait` `:254`, `xchg` `:257`, `bswap` `:52`.

Two exceptions worth calling out:

* **`call` must be a barrier.** x86 `call`/`ret` do not modify flags, and neither does a C++ call
  through `GuestContext*` (the flags are memory fields the callee does not touch unless it runs
  lifted guest code). But a `native_override` HLE function (`core/semantics/x86_64_lifter.hpp:50-54`)
  *can* re-enter guest code and clobber flags. Modelled as `reads = writes = 0` the analysis assumes
  flags survive a call, which is the conservative direction for the caller's own flags. **Keep
  `reads = writes = 0` and note the assumption in §9.4.**
* **The `ret` boundary.** A function's `ret` is where the walk starts with an empty seed, exactly as
  SR's `ret` bound does (`SRW/SR_full_win32.c:576`). This assumes no caller observes the callee's
  flags — valid per the x86 ABI, and it is the assumption most likely to be wrong on hand-written
  assembly. §9.4.

### 5.10 Operand-shape refinement (the `FL_SPECIFIC` mechanism)

`SET_FLAGS(UD_Imov, FL_NONE, FL_SPECIFIC)` (`SRW/udis86_dep.c:177`) exists because `mov`'s flag
effect depends on its operands: `mov cr0, r32` and friends have undefined flags
(`SRW/SR_full_llasm_instr.c:4233-4246`), while every other `mov` writes nothing. The refined value
is written back through `*pflags_write` (`SRW/SR_full_llasm_instr.c:7814-7815`).

Recomp Studio needs the same hook, but the only shapes that matter for us today are:

* `mov` to/from `cr*`/`dr*` → `unknown = true` (abort the function). **Not verified** whether
  Capstone surfaces control-register operands in `DecodedInstruction`; check
  `discovery::Operand::Kind` in `core/discovery/function_discovery.hpp` before relying on it.
* `movsd`/`movss`/`movaps`/… — SSE forms write no flags. SR's `UD_Imovsd`
  (`udis86_dep.c:179`) is the *string* `MOVSD` and says `FL_NONE`; it does not apply to the SSE form.
  Our lifter dispatches SSE `movsd` elsewhere; make sure the table lookup happens **after** the
  SIMD/VEX dispatch, or the two will collide.

---

## 6. Failure discipline

### 6.1 SR's escape hatches, and what each means for us

**`FL_WEAK` (`SRW/udis86_dep.h:68`)** — marks a flag *read* that the backend satisfies without
per-flag liveness. Used only three times: `lahf` (`SRW/udis86_dep.c:160`), `pushfd`
(`:203`), `pushfw` (`:204`). SR handles it at `SRW/SR_full_llasm.c:249` (if the live set is *only*
the weak marker, clear it) and `:273-276` (warn rather than error if a weak flag survives to the
region start). **Recomp Studio does not need `FL_WEAK`.** Our `lahf` reads five real fields
(`core/semantics/x86_64_lifter.cpp:690-694`) and our `pushfd` is not implemented, so there is no
"read that does not need materialising" case. Omit it. If `pushfd` is added later, its read is real
and needs no weak marker either.

**`FL_SPECIFIC` (`SRW/udis86_dep.h:69`)** — "I cannot summarise this from the mnemonic alone." It is
a *sentinel for the handler*, not a value: if it survives to the check at
`SRW/SR_full_llasm.c:224-230` it is a **hard error**. This maps onto our `FlagSummary::unknown`
(§3.2), and it must be a **whole-function fallback**, never a per-instruction conservative value —
because a wrong `writes` set silently drops a live producer.

**`FL_UNKNOWN` (`SRW/udis86_dep.h:40`, `SRW/udis86_dep.c:39-43`)** — no table entry at all. Hard
error at `SRW/SR_full_llasm.c:143-149`. For us: an unlisted mnemonic reaching the flag analysis means
the table and the lifter have drifted apart. **Hard error**, not fallback — the lifter's own
`unsupported_mnemonics_` machinery (`core/semantics/x86_64_lifter.hpp:57,73`) is the right place to
surface it.

**`FL_INST_MASK` (`SRW/udis86_dep.h:60-66`)** — SR's condition-code optimisation for the
`jcc`-then-`setcc` pattern (§1.6). **Not needed** if §4.2's fixpoint is implemented, because the
fixpoint propagates the flag across the block boundary for free. Do not port this; it is
compensating for the empty live-out seed.

### 6.2 The precise conditions under which Recomp Studio must fall back to eager flags

SR's condition is `SRW/SR_full_llasm.c:271-312`: **`flags_to_write` is non-empty when the backward
walk reaches the region's first instruction.** (With `FL_WEAK`-only → warning at `:273-276`;
otherwise `return 6` at `:307-310`.)

Translated to our block graph, that condition becomes "some block has a predecessor we did not
enumerate". The concrete disqualification rules, all of which set `analysed = false` for the
**whole function**:

| ID | Condition | Why | SR analogue |
|---|---|---|---|
| **D1** | The function contains an **indirect `jmp`** (register or memory operand). | The target may be any address inside the function, so some block's entry live set is unbounded. | SR has no analogue — its regions come from a bound list it controls; ours come from direct branches only (`core/discovery/function_discovery.cpp:169-190`). |
| **D2** | The function contains an **indirect `call`** whose target is inside the same function. | Same reason. An indirect call to an *import* or another function is fine (it returns, and `reads = writes = 0`, §5.9). | none |
| **D3** | Any direct branch target lies outside `function.instructions`. | We cannot read the target block's entry reads. | `SRW/SR_full_llasm.c:271-312` in spirit |
| **D4** | Any instruction's `FlagSummary::unknown` is true (§6.1). | Fail closed. | `SRW/SR_full_llasm.c:143-149`, `:224-230` |
| **D5** | A **variable-count shift or rotate** (`cl` operand) has a non-empty live-out set. *(Only if you choose SR's exact behaviour instead of the conservative `reads \|= writes \|= …` treatment in §5.4.)* | The instruction conditionally preserves flags, so it is neither a definite kill nor a definite preserve. | `SRW/SR_full_llasm.c:5981-5984` — SR errors verbatim. |
| **D6** | The function's **entry block has a non-empty `live_in`**. | Flags observed at function entry come from an unknown caller. | `SRW/SR_full_llasm.c:271-312` — SR's exact condition, for the region containing the entry. |
| **D7** | The function contains a `tail_call_targets` member (`core/discovery/function_discovery.hpp:44`) that is also a block start. | Ambiguous boundary between "another function" and "a block of this one". | none |

**Fallback behaviour, per the task constraint.** When any of D1–D7 fires:

1. `FunctionFlagLiveness::analysed = false`, `fallback_reason` = the rule ID and the offending
   address.
2. `emit_instruction` receives `flags_wanted = kFlagsArithmetic | kFlagDirection` — i.e. **today's
   eager behaviour**, bit-for-bit unchanged.
3. **A diagnostic is emitted.** Recomp Studio already has the shape for this: the aggregated
   diagnostic in `CoverageCensus` / `UnsupportedInstructionClass`
   (`core/semantics/x86_64_lifter.hpp:20-42`). Add a parallel, non-fatal counter:

   ```cpp
   struct FlagLivenessFallback {
     std::uint64_t function_entry{};
     std::string rule;        // "D1" .. "D7"
     std::uint64_t address{}; // offending instruction
     std::string reason;      // human-readable
   };
   ```
   surfaced on the `verify --json` report next to `unsupported_mnemonics`
   (`tests/end-to-end/recompile_test.py:145`). It must be **informational, not a failure** — a
   fallback is a missed optimisation, not a correctness problem.

**This is the one place where we should be stricter than SR.** SR's closure failure aborts the
whole recompilation. Recomp Studio's equivalent is a per-function fallback plus a diagnostic, which
is what the task asks for and what the rest of the codebase does (compare
`core/semantics/x86_64_lifter.cpp:1221-1228`, where a `LiftError` under `strict == false` emits a
`recomp_unsupported` stub rather than aborting).

---

## 7. EFLAGS constants, paste-ready

Recomp Studio stores flags as **seven separate `std::uint32_t` fields**
(`runtime/recomp_runtime.hpp:33-39`), not as a packed EFLAGS word. So there are two constant sets:

### 7.1 Analysis constants — already given in §3.1

Use `FlagMask` there.

### 7.2 Packing constants — for `lahf`/`sahf`/`pushfd`/`popfd`

These are SR's positions, transcribed from `SR/llasm-support/llasm_cpu.h:54-72` and mirrored in
`SR/llasm-support/llasm.llinc:28-46`. They are **the real x86 EFLAGS layout** and must not be
changed:

```cpp
// EFLAGS bit positions, as materialised by SR at
// SR/llasm-support/llasm_cpu.h:54-59 (shifts) and :64-72 (masks), and
// duplicated in SR/llasm-support/llasm.llinc:28-46.
inline constexpr int kEflagsShiftCarry     = 0;   // llasm_cpu.h:54
inline constexpr int kEflagsShiftParity    = 2;   // llasm_cpu.h:55
inline constexpr int kEflagsShiftAuxiliary = 4;   // llasm_cpu.h:56
inline constexpr int kEflagsShiftZero      = 6;   // llasm_cpu.h:57
inline constexpr int kEflagsShiftSign      = 7;   // llasm_cpu.h:58
inline constexpr int kEflagsShiftOverflow  = 11;  // llasm_cpu.h:59
inline constexpr int kEflagsShiftInterrupt = 9;   // llasm_cpu.h:61
inline constexpr int kEflagsShiftDirection = 10;  // llasm_cpu.h:62

inline constexpr std::uint32_t kEflagsCarry     = 0x0001u;  // llasm_cpu.h:64
inline constexpr std::uint32_t kEflagsParity    = 0x0004u;  // llasm_cpu.h:65
inline constexpr std::uint32_t kEflagsAuxiliary = 0x0010u;  // llasm_cpu.h:66
inline constexpr std::uint32_t kEflagsZero      = 0x0040u;  // llasm_cpu.h:67
inline constexpr std::uint32_t kEflagsSign      = 0x0080u;  // llasm_cpu.h:68
inline constexpr std::uint32_t kEflagsOverflow  = 0x0800u;  // llasm_cpu.h:69
inline constexpr std::uint32_t kEflagsInterrupt = 0x0200u;  // llasm_cpu.h:71
inline constexpr std::uint32_t kEflagsDirection = 0x0400u;  // llasm_cpu.h:72
// Bit 1 is architecturally always 1 and SR writes it as a literal:
// SRW/SR_full_llasm_instr.c:670-671  "... | 0x02u | ..."
inline constexpr std::uint32_t kEflagsReserved1 = 0x0002u;
```

**These are already the constants the lifter uses inline.** `core/semantics/x86_64_lifter.cpp:690-694`
(`lahf`) hardcodes `<< 7`, `<< 6`, `<< 4`, `<< 2`, and `0x02u`; `:696-700` (`sahf`) hardcodes
`>> 7`, `>> 6`, `>> 4`, `>> 2`. Replacing those literals with the named constants above is a
zero-risk cleanup that makes the two halves of the code agree by construction — worth doing as part
of this change. Note SR does the same thing from the other side:
`SRW/SR_full_llasm_instr.c:1161-1170` (`SR_disassemble_change_flags`) builds
`and/or/xor eflags, eflags, <mask>` from these masks, and `SRW/SR_full_llasm_instr.c:78-92` shows
`adc` reading carry with `and tmp5, eflags, CF`.

---

## 8. What evidence would prove the optimisation semantics-preserving

### 8.1 What the harness actually gates on today (important correction)

The brief says every fixture is differentially verified against Unicorn comparing stdout
byte-for-byte **and** the executed guest-address trace. The first half is right; **the trace is not
currently a pass/fail gate**:

* `DifferentialResult::verified()` is
  `reference_completed && candidate_completed && outputs_match`
  — `core/verification/differential_harness.hpp:35-37`. No trace.
* `compare_execution_traces` (`core/verification/differential_harness.hpp:58-60`,
  `core/verification/differential_harness.cpp:359-405`) is called from exactly one place:
  `core/harness/repair_harness.cpp:104`, and only **after** `compare_project` has already failed
  (`:95-103`), as a diagnostic.
* The per-fixture gate in `tests/end-to-end/recompile_test.py:127-146` asserts
  `reference_completed`, `candidate_completed`, `outputs_match`, no `unsupported_mnemonics`, and
  `executed_instructions > 0`. It never inspects a trace.

**Therefore the trace comparison exists but is not evidence today.** For a flag-elision bug it is
the *stronger* signal: a `jcc` that takes the wrong branch changes the executed-address sequence
immediately, even if the two paths later re-converge and print identical bytes.

### 8.2 The evidence required for this change

1. **Baseline.** Run the full suite on the current tree and record the pass set, so a regression is
   attributable. `ctest --test-dir build`, then `tests/end-to-end/recompile_test.py` directly.
2. **Byte-identical generated code when nothing can be elided.** Lift a fixture with
   `flags_wanted = kFlagsArithmetic | kFlagDirection` forced, and diff the generated
   `.cpp` against the pre-change output. It must be **identical**. This isolates the plumbing (the
   new parameter, the guarded helpers) from the optimisation and proves the defaulted mask really is
   a no-op.
3. **The optimisation is observable.** Lift the same fixture with the analysis enabled and diff the
   generated `.cpp`: the flag assignments must be a strict subset of the baseline's. If the diff is
   empty, the pass is not firing and the test below proves nothing.
4. **Every positive fixture still passes** `tests/end-to-end/recompile_test.py` — stdout
   byte-for-byte against Unicorn, which is what the gate already does.
5. **Promote the trace comparison to a gate for the flag fixtures, with a bounded limit.**
   `compare_execution_traces` already takes a `trace_limit` (`differential_harness.hpp:58-60`;
   the repair harness defaults to 4,000,000 — `core/harness/repair_harness.hpp:16`). Add a check
   that `TraceComparison::diverged == false` for at least `eflags`, `flagprobe`, `bitops`, `arith`,
   `wide` and `pe32_arith`. This is the check that would catch a flag elision which changes control
   flow but not output, and it is the reason to do this change behind a gate rather than on trust.
   Without it, a wrong-branch-that-reconverges bug is invisible to the suite.
6. **Negative control.** Deliberately break one entry of the table (e.g. make `jz` read `CF` instead
   of `ZF`) and confirm the suite **fails**. A test suite that cannot fail on a known-bad table
   proves nothing about the table.

### 8.3 Existing fixture coverage of flags

From reading `tests/fixtures/apps/` and `tests/end-to-end/recompile_test.py:22-46`:

| Fixture | Flag coverage | Verdict |
|---|---|---|
| `eflags.c` | `add`, `sub`, `inc`, `dec`, `and`, `cmp`, `neg`, `imul`, `shl` (counts 0–3). Captures CF/PF/AF/ZF/SF via `lahf` and OF via `seto` (`eflags.c:20-168`), prints a checksum (`:205-206`). Operand set `{0, 1, 0x7fffffff, 0x80000000, 0xffffffff, 0x12345678}` (`:172`). Explicitly masks AF (undefined for shifts) and OF for count > 1 (`:193-201`). | **Strong** — the single best fixture for this change. |
| `flagprobe.c` | `add`, `sub`, `and`, `xor`, `or`, `imul`, `inc`, `dec`, `neg`, `shl1`, `cmp`, `shln` (1–3); one printed line per (op, operands) (`flagprobe.c:108-125`). | **Strong** — localises a mismatch to one operation. |
| `bitops.c` | `bt`/`bts`/`btr`/`btc` register forms, CF read via `setc` (`bitops.c:49-60`). | **Good** — and it explicitly guards against the `btr` mask bug that the lifter's own comment records (`core/semantics/x86_64_lifter.cpp:529-533`). |
| `wide.c` | 64-bit `add`/`mul`/`shr`/`div` and 64-bit shift flag effects (`wide.c:1-20`). | **Good** for 64-bit widths. |
| `arith.c` / `pe32_arith` | General arithmetic + heavy `jcc` via C control flow, recursion, arrays (`arith.c:1-24`). No explicit flag capture. | **Indirect** — exercises `jcc`/`setcc`/`cmovcc` wherever the compiler emits them, but asserts nothing about flags directly. |
| `x87.c`, `byteops.c`, `calls.c`, `memory.c`, `aliasing.c`, `simd_convert.c`, `vex.c`, `tictactoe.c`, `snake.c` | No flag assertions (`byteops` exercises DF, `x87` exercises the x87 status word). | Not flag evidence. |

**Not covered by any fixture** (verified by grepping the fixture sources for the mnemonics):
`adc`, `sbb`, `rcl`, `rcr`, `rol`, `ror`, `shld`, `shrd`, `xadd`, `cmpxchg`, `bsf`, `bsr`,
one-operand `mul`, `pushf`/`popf`, and the `jo`/`jno`/`seto`/`setp` conditions.

**Additional coverage the change needs.** Add a fixture — call it `flagliveness.c` — that pins the
cases the pass actually decides, and that would pass under eager flags and fail under a wrong
elision. The minimum set:

1. **Dead producer**: `add` whose flags are overwritten by a later `cmp` before any read. Under
   eager flags this passes trivially; under a correct pass the `add`'s flags are gone and the result
   must still be identical. Assert on the `add`'s *result*, printed.
2. **Live producer across a conditional branch**: `cmp` in block A, `jz` at the start of block B
   (force this by writing the branch so the compiler splits the block). This is the case SR's
   region-local pass **cannot** handle and the fixpoint can.
3. **`adc`/`sbb` chains**: carry in and carry out across at least three links, printed. This is the
   only way to catch a `CF`-read being modelled as a `CF`-write.
4. **`div`/`idiv` flag pass-through**: set CF/ZF/SF/OF to known values with `stc`/`clc` and an
   arithmetic op, then `div`, then read the flags back with `lahf`/`seto` and print them. This pins
   §9.1(a) — the one place where SR's table is actively wrong for us. Without it, a copied-from-SR
   `FL_COND` row on `div` passes the suite silently.
5. **`rcl`/`rcr`**: same as (3), for the through-carry rotates.
6. **Variable-count shift with live flags**: `shl %cl, %eax` followed by `lahf`/`setc`, over counts
   `{0, 1, 31, 32, 33}`. **This is the single highest-value new test** — it is the case SR hard-errors
   on (`SRW/SR_full_llasm_instr.c:5981-5984`) and the case our `effective == 0` early-out makes
   subtle (`runtime/recomp_runtime.hpp:224-225`).
7. **`cmpxchg`**: the intra-instruction ZF read (§9.3).
8. **`lahf`/`sahf` round-trip**: pack, perturb a register, unpack, `setcc` — catches any elision that
   removes one of the five `lahf` inputs.
9. **Every flag as the sole live flag**: eight variants where exactly one flag is read, so that an
   off-by-one in the mask shows up as a specific variant failing.

Keep it deterministic and textual, matching the existing style (`tests/fixtures/apps/fy.h`), and add
it to `FIXTURES_X64` in `tests/fixtures/apps/build.sh:21` and to `FIXTURES` in
`tests/end-to-end/recompile_test.py:22-35` with pinned output fragments in `EXPECTED_OUTPUT`.

---

## 9. Honest risk list

### 9.1 The table must match the helper, not the SDM and not SR — and `div`/`idiv` is the trap

**This is the single most likely way to get this change wrong**, and there are two distinct variants.

**(a) A `writes` set that is too *large*.** Every "over-approx" note in §5 has this shape: SR lists a
*superset* of the flags an instruction really modifies. For SR that is safe **only because** SR
aborts when the live set does not close (`SRW/SR_full_llasm.c:271-312`). Over-approximating `writes`
makes the analysis believe a flag was killed when it was not; if a later instruction reads that flag,
the producer is elided and the reader sees a stale value.

**SR's `div`/`idiv` rows are an instance of this that is actively wrong for us.** SR says
`SET_FLAGS(UD_Idiv, FL_NONE, FL_COND)` (`SRW/udis86_dep.c:71`) and
`SET_FLAGS(UD_Iidiv, FL_NONE, FL_COND)` (`:127`), but our `unsigned_divide`
(`runtime/recomp_runtime.cpp:545-557`) and `signed_divide` (`:559-574`) **write no flags at all** —
they only compute and return. Transcribing SR's row would make the pass believe `div` kills CF and
therefore elide the CF producer before it; a subsequent `adc` would read stale CF, where the current
eager code correctly reads the pass-through value. **Use `reads = writes = 0`** (§5.3).

The same shape appears benignly for `and`/`or`/`xor`/`test`
(`SRW/udis86_dep.c:48,191,248,259` all say `FL_COND = CF|PF|AF|ZF|SF|OF`): real `and` leaves AF
*undefined* and clears CF/OF, but `runtime/recomp_runtime.hpp:160-166` shows our `bitwise_and` really
does write `carry_flag = overflow_flag = auxiliary_flag = 0`, so here the over-approximation happens
to match. **But that is a coincidence of our implementation,
not a property of the ISA** — if `bitwise_and` is ever changed to leave CF alone, this table becomes
wrong silently. **Mitigation:** add a static assertion or a comment pairing each table row with the
helper it must match, and add the `adc`-after-`and` case to the new fixture.

### 9.2 Undefined flags are the second most likely source of a wrong answer

The Intel SDM leaves several flag results *undefined*, meaning a real CPU may produce any value and
the guest may not legally depend on it — but our Unicorn reference **will** produce a specific value,
and a differential test compares against it. So "undefined" does not mean "don't care" for us; it
means "must match whatever the emulator does".

Affected, per the SDM and per SR's handler comments:

* `mul`/`imul`: SF, ZF, AF, PF undefined (`SRW/SR_full_llasm_instr.c:3240` for `imul`). **Our helpers
  define all four** — `signed_multiply_single` (`runtime/recomp_runtime.cpp:492-511`),
  `signed_multiply_two` (`:513-531`) and `unsigned_multiply_single` (`:533-543`) each zero AF and call
  `update_zero_sign_parity`. So the table says all six (see §5.3).
* `div`/`idiv`: SF, ZF, AF, PF, CF, OF all undefined. **Our helpers write nothing** — see §9.1(a).
* `shl`/`shr`/`sar`: AF undefined; OF undefined for count > 1
  (`SRW/SR_full_llasm_instr.c:5973`).
* `rol`/`ror`: only CF and OF defined (`SRW/udis86_dep.c:211-212`); our helpers additionally zero AF
  (`runtime/recomp_runtime.hpp:305,319`).
* `shld`/`shrd`: AF undefined; OF/SF/ZF/PF undefined when count > 1.
* `bt`/`bts`/`btr`/`btc`: only CF defined for the register form
  (`SRW/udis86_dep.c:53-54` says `FL_COND` — over-approximated).
* `bsf`/`bsr`: ZF defined, everything else undefined.
* `xadd`/`cmpxchg`: `cmpxchg` writes all six; `xadd` writes all six.

The `eflags.c` fixture already demonstrates the right discipline for this — it masks AF for shifts
and OF for count > 1 before checksumming (`eflags.c:193-201`), because those bits are not
comparable. **The new fixture must do the same**, and the table should record the *defined* set with
a comment naming the undefined ones, so a future reader does not "fix" the table to the SDM's
undefined set and silently stop matching Unicorn.

### 9.3 Intra-instruction flag reads

Two instructions in the current lifter **read a flag they just wrote**, inside the same emitted
statement:

* `cmpxchg`, `core/semantics/x86_64_lifter.cpp:948-952`:
  ```cpp
  compare_with_flags(context, accumulator, original, width);
  if (context->zero_flag) { ...store source... } else { ...store original... }
  ```
  `compare_with_flags` (`runtime/recomp_runtime.hpp:187-189`) writes ZF and the next statement reads
  it. If the table says `cmpxchg` writes ZF and the liveness pass finds ZF dead after the
  instruction, the pass will ask for ZF not to be materialised — and the emitted `if` reads a stale
  value. **Fix:** the summary for `cmpxchg` must have `reads |= kFlagZero` (or the lifter must be
  restructured so the ZF test is folded into the helper). The same applies to any future
  instruction whose emitted body branches on a flag it computes.
* `increment_with_flags` / `decrement_with_flags`
  (`runtime/recomp_runtime.hpp:191-203`) read `carry_flag`, save it, and restore it. That is a
  read+write of CF, correctly captured by `inc`/`dec` having `writes` without CF — but the *read* is
  an implementation detail inside the helper, not a guest-visible read. **No table entry needed**;
  note it so nobody adds a spurious `reads |= kFlagCarry`.

**General rule to encode in the emitter:** `flags_wanted` for an instruction must always include
every flag that instruction's own emitted code reads. Assert this in a debug build.

### 9.4 The `ret` and `call` boundary assumptions

The analysis assumes flags are dead at a function's `ret` (SR's `ret` bound,
`SRW/SR_full_win32.c:576`, plus the empty seed at `SRW/SR_full_llasm.c:45`) and preserved across a
`call` (§5.9). Both match the x86 ABI and both are violated by some hand-written assembly. SR takes
the same position. **The differential harness is what makes this safe for us** — a guest that really
does rely on its callee's flags will diverge, and the trace comparison (§8.2 item 5) will localise
it to the exact instruction. **Mitigation:** if a fixture ever fails here, add the offending function
to a `flag_preserving_calls` override list rather than weakening the analysis globally.

### 9.5 The parity flag is the one flag SR and Recomp Studio compute differently

SR computes parity where it needs it; Recomp Studio uses `__builtin_parity(...) ^ 1`
(`runtime/recomp_runtime.hpp:121-127`). Parity is only defined on the low 8 bits of the result, and
`update_zero_sign_parity` correctly masks to `result & 0xff` before the builtin. **No action needed**
— but if a table row ever says an instruction does not write PF and the helper does, PF liveness
will be wrong. `and`/`or`/`xor`/`test` all go through `update_zero_sign_parity`, so they all write
PF; the table rows in §5.2 reflect that.

### 9.6 Partial-register writes

The table is keyed by mnemonic, not by operand width, and that is correct for flags — flags do not
depend on which sub-register was written. But `eflags.c` and `flagprobe.c` both use 32-bit operations
and `wide.c` uses 64-bit, and the **width** affects the sign/overflow bit position, not the flag
identity. The liveness pass is width-agnostic and must stay that way. **Risk:** someone "helpfully"
keys the table on width and breaks `wide.c`. Put a comment on the table saying so.

### 9.7 What does **not** transfer from SR

Being explicit, since the point of the spec is to port the right thing:

1. **SR's empty live-out seed** (`SRW/SR_full_llasm.c:45`). Does not transfer — our blocks are not
   basic blocks (§2.1) and we have no bound list guaranteeing the terminator is inside the region.
   Replaced by the §4.2.2 fixpoint.
2. **SR's `FL_INST_MASK` / `iflags` mechanism** (`SRW/udis86_dep.h:60-66`,
   `SRW/SR_full_win32.c:204-250`). Does not transfer — it is a hand-written patch for the one
   cross-block flow SR's block-local analysis cannot see. The fixpoint handles it generally.
3. **SR's `FL_WEAK`** (`SRW/udis86_dep.h:68`). Not needed; we have no read that is satisfied without
   materialising the flag (§6.1).
4. **SR's hard abort on closure failure** (`SRW/SR_full_llasm.c:307-310`). Should not transfer —
   Recomp Studio's convention is a per-function fallback plus a diagnostic, matching
   `core/semantics/x86_64_lifter.cpp:1216-1221`.
5. **SR's `eflags`-as-a-packed-word representation** (`SR/llasm-support/llasm_cpu.h:29-40`). Does
   not transfer — our `GuestContext` has seven separate `std::uint32_t` fields
   (`runtime/recomp_runtime.hpp:33-39`). The *bit positions* still matter for `lahf`/`sahf`/`pushfd`
   (§7.2) and the *mask vocabulary* still maps cleanly (§3.1), but the storage does not.6. **SR's "abort on unknown instruction"** (`SRW/SR_full_llasm_instr.c:7749-7753`). Already handled
   differently here by `unsupported_mnemonics_` / `CoverageCensus`
   (`core/semantics/x86_64_lifter.hpp:20-42,57`); the flag analysis should reuse that machinery, not
   duplicate it.
7. **SR's guard on emission** (`SRW/SR_full_llasm_instr.c:3248`,
   `if (flags_to_write & (FL_CARRY | FL_OVERFLOW))`) is a *source-level* `if` in the recompiler.
   Ours is a *runtime* `if` inside an `inline` helper with a compile-time-constant mask, which clang
   folds away. Same idea, better mechanism for a C++-emitting lifter — this is the one place where
   emitting C++ beats emitting assembly.

### 9.8 Effort estimate and recommended sequencing

| Step | Work | Risk | Payoff |
|---|---|---|---|
| 1 | `FlagMask` + `FlagSummary` + table (§3, §5) | low | none on its own; prerequisite |
| 2 | `flags_wanted` parameter + guarded helpers + the byte-identical check (§8.2 item 2) | low | none on its own; **proves the plumbing is a no-op** |
| 3 | Step 1 algorithm — function-wide `R_all` (§4.1) | **very low** | large: most functions stop computing 5 of 6 flags |
| 4 | Promote the trace comparison to a gate for the flag fixtures (§8.2 item 5) | low | makes step 5 debuggable |
| 5 | New `flagliveness.c` fixture (§8.3) | low | makes step 6 safe |
| 6 | Step 2 algorithm — block graph + fixpoint (§4.2) + D1–D7 (§6.2) | medium | incremental over step 3 |

**Do 1–5 before 6.** Steps 3 and 4 are independent of the harder analysis and each is worth landing
alone. If step 6 turns out to disqualify most functions (D1 in particular may be common in real
binaries with jump tables), step 3's win still stands and nothing is lost.

---

## 10. Summary of every SR citation used

| Claim | SR location |
|---|---|
| Flag vocabulary and bit values | `SRW/udis86_dep.h:39-70` |
| Composite sets `FL_AH`/`FL_COND_SUB`/`FL_COND`/`FL_ALL` | `SRW/udis86_dep.h:54-58` |
| `FL_INST_*`, `FL_WEAK`, `FL_SPECIFIC` | `SRW/udis86_dep.h:60-69` |
| Summary arrays | `SRW/udis86_dep.h:72-73` |
| `SET_FLAGS` macro | `SRW/udis86_dep.c:29-32` |
| `FL_UNKNOWN` default | `SRW/udis86_dep.c:39-43` |
| The whole per-mnemonic table | `SRW/udis86_dep.c:45-259` |
| Backward pass | `SRW/SR_full_llasm.c:32-316` |
| Empty live-out seed | `SRW/SR_full_llasm.c:45` |
| Table lookup | `SRW/SR_full_llasm.c:141-142` |
| `FL_UNKNOWN` → error | `SRW/SR_full_llasm.c:143-149` |
| Generator receives the live set | `SRW/SR_full_llasm.c:203` |
| `FL_SPECIFIC` → error | `SRW/SR_full_llasm.c:224-230` |
| Live-set update | `SRW/SR_full_llasm.c:248-255` |
| Reverse-address step | `SRW/SR_full_llasm.c:260-268` |
| Closure check (the failure condition) | `SRW/SR_full_llasm.c:271-312` |
| Closure failure error | `SRW/SR_full_llasm.c:307-310` |
| Variable-count shift + live flags → error | `SRW/SR_full_llasm_instr.c:5981-5984` |
| Immediate count 0 → `flags_write = 0` | `SRW/SR_full_llasm_instr.c:6009-6016` |
| Shift flag comment | `SRW/SR_full_llasm_instr.c:5973` |
| Handler may refine the summary | `SRW/SR_full_llasm_instr.c:1620,1636-1637,7814-7815` |
| Operand-shape refinement for `mov` | `SRW/SR_full_llasm_instr.c:4233-4246` |
| Emission guarded on liveness | `SRW/SR_full_llasm_instr.c:3248` |
| `imul` flag comment | `SRW/SR_full_llasm_instr.c:3240` |
| `lahf`/`sahf` emission | `SRW/SR_full_llasm_instr.c:4078-4083` |
| `SR_disassemble_change_flags` | `SRW/SR_full_llasm_instr.c:1161-1170` |
| `adc` reading carry via a mask | `SRW/SR_full_llasm_instr.c:78-92` |
| Region construction | `SRW/SR_full.c:341-388,482-540` |
| `jcc`/`jcxz` region bounds | `SRW/SR_full_win32.c:619-627` |
| `loop*` region bounds | `SRW/SR_full_win32.c:845-847` |
| `call` region bounds | `SRW/SR_full_win32.c:365-366,550-551` |
| `ret`/`retf`/`iret` region bounds | `SRW/SR_full_win32.c:576,962-963,560` |
| `jmp` region bound | `SRW/SR_full_win32.c:689-690` |
| `jcc`→`setcc` cross-region stitching | `SRW/SR_full_win32.c:204-250,610-616,1128-1135` |
| EFLAGS bit positions and masks | `SR/llasm-support/llasm_cpu.h:54-72` |
| Same constants in the llasm runtime | `SR/llasm-support/llasm.llinc:28-46` |
| Unknown instruction aborts | `SRW/SR_full_llasm_instr.c:7749-7753` |

## 11. Summary of every Recomp Studio citation used

| Claim | Location |
|---|---|
| `DecodedInstruction` / `RecoveredFunction` fields | `core/discovery/function_discovery.hpp:31-45` |
| `direct_branch_target` (private, immediate only) | `core/discovery/function_discovery.cpp:89-94` |
| `block_starts` population (no conditional fall-through) | `core/discovery/function_discovery.cpp:142,169-190` |
| Lifter private interface | `core/semantics/x86_64_lifter.hpp:63-73` |
| `emit_instruction` signature and `emit` lambda | `core/semantics/x86_64_lifter.cpp:328-334` |
| `lift_function` (where the map is computed) | `core/semantics/x86_64_lifter.cpp:1189-1199` |
| `strict == false` fallback precedent | `core/semantics/x86_64_lifter.cpp:1216-1221` |
| Condition-code spellings | `core/semantics/x86_64_lifter.cpp:51-69` |
| `setcc` / `cmovcc` / `jcc` dispatch | `core/semantics/x86_64_lifter.cpp:736-746,789-790` |
| `lahf` / `sahf` inline bit arithmetic | `core/semantics/x86_64_lifter.cpp:690-700` |
| `bt`/`bts`/`btr`/`btc` emission | `core/semantics/x86_64_lifter.cpp:518-539` |
| Shift/rotate dispatch | `core/semantics/x86_64_lifter.cpp:634-643` |
| `imul`/`mul`/`div`/`idiv` emission | `core/semantics/x86_64_lifter.cpp:645-680` |
| `bsf`/`bsr` emission | `core/semantics/x86_64_lifter.cpp:924-936` |
| `xadd`/`cmpxchg` emission (intra-instruction ZF read) | `core/semantics/x86_64_lifter.cpp:937-955` |
| `cld`/`std` | `core/semantics/x86_64_lifter.cpp:822-823` |
| `GuestContext` flag fields | `runtime/recomp_runtime.hpp:30-51` |
| `update_zero_sign_parity` | `runtime/recomp_runtime.hpp:121-127` |
| `add_with_flags` / `subtract_with_flags` | `runtime/recomp_runtime.hpp:129-150` |
| `add_with_carry` / `subtract_with_borrow` | `runtime/recomp_runtime.hpp:151-158` |
| `bitwise_and/or/xor`, `test_with_flags`, `compare_with_flags` | `runtime/recomp_runtime.hpp:160-189` |
| `increment_with_flags` / `decrement_with_flags` / `negate_with_flags` | `runtime/recomp_runtime.hpp:191-214` |
| `bitwise_not` | `runtime/recomp_runtime.hpp:216-218` |
| Shift helpers and their `effective == 0` early-out | `runtime/recomp_runtime.hpp:220-294` |
| Rotate helpers (CF read; AF zeroing) | `runtime/recomp_runtime.hpp:296-355` |
| `evaluate_condition` | `runtime/recomp_runtime.hpp:361-380` |
| `bit_scan_reverse` / `bit_scan_forward` | `runtime/recomp_runtime.hpp:542-560` |
| `signed/unsigned_multiply`, `unsigned/signed_divide` flag writes | `runtime/recomp_runtime.cpp:492-574` |
| `DifferentialResult::verified()` (stdout only) | `core/verification/differential_harness.hpp:35-37` |
| `TraceComparison` and `compare_execution_traces` | `core/verification/differential_harness.hpp:40-48,58-60` |
| Trace comparison implementation | `core/verification/differential_harness.cpp:359-405` |
| Trace used only as a post-failure diagnostic | `core/harness/repair_harness.cpp:95-104` |
| Default trace limit | `core/harness/repair_harness.hpp:16` |
| Per-fixture gate assertions | `tests/end-to-end/recompile_test.py:127-146` |
| Fixture list | `tests/end-to-end/recompile_test.py:22-46` |
| Fixture build lists | `tests/fixtures/apps/build.sh:21,24,28,60` |
| `eflags.c` coverage | `tests/fixtures/apps/eflags.c:20-206` |
| `flagprobe.c` coverage | `tests/fixtures/apps/flagprobe.c:11-125` |
| `bitops.c` coverage | `tests/fixtures/apps/bitops.c:1-71` |
| `wide.c` coverage | `tests/fixtures/apps/wide.c:1-20` |
| `arith.c` coverage | `tests/fixtures/apps/arith.c:1-24` |

---

*Spec prepared by teammate `sr-analyst` for task-7. Write scope: this file only. No code was
modified, and `reports/sr-analysis.md` was not touched after this task began.*
