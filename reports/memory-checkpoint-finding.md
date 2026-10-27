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

## Not established

Which side is wrong, and the trace does not settle it. Either

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
