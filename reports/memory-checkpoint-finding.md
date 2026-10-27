# The guest-memory checkpoint divergence: what was established

Status: **not resolved**. This records the diagnosis so far, precisely, because the
finding is a candidate correctness issue and must not be lost or guessed at.

## What the comparison does

At every 1000th executed guest instruction, both sides digest two bounded windows
with FNV-1a:

- the **live stack**, `[ESP, ESP + 0x1000)`;
- the **image's writable area**, `[image_base, image_base + 0x10000)`.

The digest is reported by `verify` and does **not** gate the verdict, because it
fails for a reason that is not yet understood. `--checkpoints memory` is therefore
declared *planned* rather than implemented.

## Established

1. **The checkpoints line up.** Candidate and reference record the same index at
   the same guest address: checkpoint 0 at `0x140001bc0`, 1000 at `0x1400017ab`,
   2000 at `0x1400017a5`. The counters are not drifting, so this is not a
   checkpoint-alignment artefact.

2. **The data window matches exactly.** At checkpoint 175, `[image_base,
   image_base + 0x10000)` is byte-identical between the two sides: **0 differing
   bytes of 65536**.

3. **The stack window differs in one 8-byte slot.** At checkpoint 175, four bytes
   differ, at `ESP+56`:

   | | bytes at ESP+56 |
   |---|---|
   | reference | `78 10 00 40 01 00 00 00` = `0x0000000140001078` |
   | candidate | `01 00 00 00 05 00 00 00` |

   The neighbouring slots agree (`3`, `2`, `1`, `0x35` at ESP+64 onward).

4. **`0x140001078` is a return address.** Disassembling the original
   `arith.exe`:

   ```
   0x140001076  call  rbx
   0x140001078  add   rsp, 0x48      <-- the value on the reference's stack
   0x14000107c  pop   rbx
   ```

   So the reference holds the return address of an **indirect call through a
   register**, and the candidate holds `1` in that slot.

## Corrected on the way

The first version of the digest covered `[ESP - 0x1000, ESP)` and reported a
divergence at **checkpoint 1**. That was a defect in the digest, not in the
translation: memory *below* the stack pointer is dead. The program has moved past
it and cannot read it again, and the two sides legitimately differ there — the
reference had a return address at `ESP-104` that it had popped, and the candidate
had overwritten it. Nothing observable differed. Digesting the live stack instead
moved the first divergence from checkpoint 1 to checkpoint 175, which is what made
the remaining difference small enough to isolate.

## Established since: the control flow is identical

The two executed-instruction streams were captured and compared —
`RECOMP_TRACE` on the candidate, `RECOMP_REF_TRACE` on the reference, both writing
the address of every executed guest instruction as a 64-bit word.

```
reference: 177195 addresses
candidate: 177195 addresses
THE INSTRUCTION STREAMS ARE IDENTICAL
```

Byte for byte, in the same order. This is therefore **not** a control-flow
divergence and not a counter drift: the two sides execute exactly the same guest
instructions. Combined with the register and flag agreement at every checkpoint
and the exact agreement of the writable data window, what remains is a difference
in **what one side stored to one stack slot**, under identical control flow.

That is a much smaller question than the one this investigation started with, and
it is where the next attempt should begin.

## Established since: the store logs name the store

Every guest store is now logged on both sides — `RECOMP_STORE_LOG` on the
candidate, `RECOMP_REF_STORE_LOG` on the reference, both writing
`instruction address value width` per line — so a divergence is attributed to the
store that caused it rather than to the byte that ended up wrong.

On `arith.exe`: 24,851 stores from the reference, 24,780 from the candidate. The
first real difference is a store the reference makes and the candidate does not:

```
reference: 140001758 167ffff08 14000175a 8
candidate: (no store at instruction 140001758)
```

`0x140001758` disassembles to `call rdi` — an **indirect call through a
register** — and `0x14000175a` is the address of the next instruction, so the
reference is logging the return address the emulated `call` pushed.

The candidate does not write it, and the reason is in the runtime:

```cpp
const auto thunk = lookup_import_thunk(target);
if (thunk >= 0) {
  // Only 32-bit x86 needs the return address pushed: its cleanup pass then
  // removes the return address and the stdcall arguments. On x86-64 the shim
  // returns directly and the guest stack must be left untouched.
  invoke_import_thunk(context, thunk, return_address, guest_pointer_width < 8);
```

On x86-64 `push_return` is false, so no push happens. The reference's emulated
`call` pushes and `emulate_shim` pops, leaving the bytes behind; the candidate
neither pushes nor pops. **Both end at the same stack pointer**, which is why the
registers agree at every checkpoint and why this shows up only as one written slot.

The first entry in the candidate's log has no counterpart in the reference —
`0 167fffff8 0 8`, the entry sentinel — because the reference writes that one with
`uc_mem_write` rather than by executing an instruction. That is a harness artefact
and is not the divergence.

## Reading of this finding

The candidate is self-consistent: same stack pointer, same registers, same flags,
same writable data, same instruction stream, same output. What differs is a byte
the **reference** wrote while emulating a `call` and then popped. On that reading
this is a harness asymmetry rather than a translation bug — the two sides disagree
about a slot neither can observe after the pop.

It cannot be called resolved on that reasoning alone, because the slot later falls
*above* the stack pointer at checkpoint 175 and is therefore live by then. The way
to settle it is to make the candidate faithful to hardware rather than merely
self-consistent: a real `call` writes the return address to memory, and having the
x86-64 thunk path do the same — pushing and popping it — would make the two sides
agree by construction instead of by argument.

## Resolved for 19 of 22 fixtures

The x86-64 thunk path now writes the return address, and the divergence on
`arith.exe` is gone: `memory: True`, `status: pass`.

Measured across every fixture with checkpoints:

```
memory agrees: 19   disagrees: 3
  pe32_simd_convert.exe: checkpoint 12 at 0x401048
  simd_convert.exe:      checkpoint 7  at 0x140001039
  x87.exe:               checkpoint 3  at 0x1400010a8
```

The three that still disagree are all **floating-point** fixtures. That is a
separate divergence from the one this report was opened for, and it is consistent
with the documented x87 limit — the guest's x87 registers are held as doubles, so a
value that needs more than 53 mantissa bits does not survive the round trip through
80-bit extended, and `fstp tbyte ptr` would therefore store a different value on
each side. **That is a hypothesis, not a finding**: the disassembly at those
addresses did not decode cleanly enough to confirm an x87 store, and it is recorded
here as the next thing to check rather than as a conclusion.

`--checkpoints memory` therefore stays declared **planned**, but the reason is now
specific and small: three floating-point fixtures, not the whole corpus.

## Not established

Whether the x87 precision limit explains the three remaining fixtures. Either

- the candidate writes `1` into a slot where the reference's frame still holds the
  return address of the `call rbx` at `0x140001076`, which would mean the
  candidate is clobbering its caller's frame; or
- the reference leaves a stale return address in a slot the candidate legitimately
  reuses, which would mean the digest is over-strict at that address.

The two are distinguishable, and the next step is a trace: record the guest
instructions between checkpoint 174 and 175 on both sides and diff them, then look
at what writes `ESP+56`. If the instruction streams agree and only the memory
differs, the candidate's store is at fault; if the streams diverge before that
store, the divergence is upstream of it.

`reports/ir-migration-surface.md` records that the lifter emits
`invoke_guest_indirect(context, <expr>, <return_address>)` for an indirect call,
and `runtime/recomp_runtime.cpp` handles the return address in
`invoke_import_thunk` and `invoke_guest_indirect`. That is where a stack-discipline
difference for `call rbx` would live.
