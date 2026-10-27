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

## Established since: the two sides disagreed about what an instruction is

Comparing the streams for `x87.exe` showed the reference **repeating the same
address** while the candidate advanced:

```
9253: ref=0x140001909 cand=0x140001909
9254: ref=0x140001909 cand=0x140001909
9255: ref=0x140001909 cand=0x14000190b   <-- first difference
```

`0x140001909` is `rep movsb`. A `rep`-prefixed instruction is **one guest
instruction** that the emulator runs once per iteration, and Unicorn fires the code
hook for each; the candidate lifts it as a single `string_move` call and traces it
once. So the reference's stream, its instruction count and its checkpoint indices
all advanced once per byte copied.

That is a defect in the **harness**, not in the translation, and it is not confined
to this fixture: every program that executes a string instruction had the two sides
counting different things from that point on. The hook now collapses consecutive
repeats, which counts a `rep` once — what the guest instruction stream actually
contains. A loop that revisits an address does not repeat it consecutively, so it is
unaffected.

With that fixed, the streams for `x87.exe` are identical: 9948 addresses each.

## Established since: the x87 hypothesis is refuted

The store log records the width of every store, so the x87 precision hypothesis
could be tested directly rather than argued about. On `x87.exe`, over 2,204
reference stores, the widths are:

```
reference widths: {1: 544, 2: 13, 4: 337, 8: 1310}
```

**There are no 10-byte stores at all.** The hypothesis was that a `tbyte` store
would round-trip a double through 80-bit extended and differ on the two sides; the
program never stores a `tbyte`, so that cannot be the cause. The hypothesis is
refuted, not confirmed.

## Established since: the logs disagree about granularity, not about stores

The first difference is a store the candidate logs and the reference splits:

```
6: ref  instr=14000141f addr=167ffff80 w=8
   cand instr=14000141f addr=167ffff80 w=16
7: ref  instr=14000141f addr=167ffff88 w=8
   cand instr=140001427 addr=167ffff90 w=16
```

`0x14000141f` is `movaps xmmword ptr [rsp+0xb0], xmm6`. The candidate records one
16-byte store; Unicorn reports it as two 8-byte writes. So the two logs describe the
same writes at different granularity, and the count difference (2,204 against 2,531)
is that, not a behavioural difference.

The candidate's vector stores were not logged at all before this round — they write
memory directly rather than through `store_guest_memory` — so the log was missing
every SSE store. That is fixed.

Merging adjacent same-instruction writes in the reference was tried and **withdrawn**:
it produced widths of 3, 5, 6, 7 and 19, which no x86 instruction can store, because
a single instruction making two genuinely separate stores is indistinguishable from
one store the emulator split. The normalisation that avoids the question is to
compare the logs **per instruction** — the set of ranges each instruction wrote —
and that is not yet implemented.

## Established since: the reference's store log cannot see shim writes

Comparing the logs per instruction -- grouping by instruction and comparing the set
of byte ranges each one wrote -- removes the granularity noise and leaves a concrete
difference. At `0x14000146b`:

```
reference: [('0x167fffec8', '0x167fffed0')]
candidate: [('0x167fffec8', '0x167fffed0'), ('0x167ffff70', '0x167ffff74')]
```

The candidate writes an extra 4 bytes. `0x14000146b` is `call rbx`, an indirect call
through a register, and the extra store is a **shim write**: the value is the byte
count a `WriteFile` would report, written to the caller's `lpNumberOfBytesWritten`.

The reference's log cannot contain it. The reference dispatches through the same
shim as the candidate, and that shim writes to `guest_memory` with a host `memcpy` --
which Unicorn never observes as a guest memory access, so `UC_HOOK_MEM_WRITE` does
not fire. **The reference's store log is blind to every write a shim performs.**

That is a limitation of the instrument, not a difference between the two programs:
both sides perform the write, into their own copy of `guest_memory`, and the memory
digest sees it on both. It means the store logs are comparable for guest
instructions and not for shim calls, and the comparison has to say which it is
looking at.

The per-instruction comparison is kept as `tools/compare_store_logs.py`; it is what
made this visible.

## Established since: every guest store agrees

Shim writes are now marked at the source rather than inferred. `guest_in_shim` is set
around every shim invocation -- including the thunk table's direct call, which
bypassed it at first and left 335 shim stores indistinguishable from guest stores.

With them marked and filtered, the per-instruction comparison reports:

```
reference: 1985 instructions that store
candidate: 1979 instructions that store
instructions whose written ranges differ: 0
```

**Every guest store agrees.** The differences the comparison had been reporting were
all shim stores, and the earlier "216 instructions whose written ranges differ" was
entirely that.

That is a strong narrowing, and it points somewhere specific: the remaining memory
divergence is **not a guest store**. It must be a write a shim performs, because
that is the only class of write the comparison cannot see -- the reference's log is
blind to shim writes by construction, so a shim that stores a *different value* on
each side is invisible to the store comparison while still showing up in the memory
digest.

The prime candidate is `WriteFile`, which writes the byte count to the caller's
`lpNumberOfBytesWritten`: the reference captures output into a string and accepts
the whole buffer, while the candidate writes to a real descriptor and accepts
whatever the host took. If those differ, the two sides store different counts -- and
`arith.exe` is a program whose entire output goes through `WriteFile`.

That is a hypothesis with a specific test, not a finding. It would be settled by
logging the *value* a shim stores on the candidate (the log already records it for
scalar stores) and comparing it against the reference's memory at the same address.

## Resolved: it is x87 environment state

Dumping the memory at checkpoint 3 on both sides and diffing it localises the
divergence to four bytes at **ESP+332**, in the live stack window:

```
  reference: 00 00 d8 3f 00 00 00 00 00 0c 00 00 ...
  candidate: 00 00 d8 3f 00 00 00 00 7f 0e 7f 02 ...
```

| | value at ESP+332 |
|---|---|
| reference | `0x00000c00` |
| candidate | `0x027f0e7f` |

`0x027f` is the x87 **control word** default, and the high half `0x0e7f` has TOP=1 in
bits 11-13 — the x87 **status word**. So the candidate has written a control word and
status word pair, which is what `fnstenv`/`fnsave` do, and the reference holds
something else in that slot.

The data window matches exactly: 0 differing bytes of 65536. Only this one stack slot
differs.

**The `WriteFile` hypothesis is refuted.** The difference is x87 state, not a byte
count, and the store-log comparison could not see it because the write happens inside
a shim — which is exactly the blind spot recorded above.

That is consistent with the documented x87 limitation (registers held as doubles, no
register tags, no full environment model), and it is now specific: `x87.exe`,
`simd_convert.exe` and `pe32_simd_convert.exe` are the three fixtures that execute
`fnstenv`/`fnsave`, and the divergence is in the environment those instructions
write.

## Resolved: it is the x87 status word, and the store is an ordinary one

The differing slot is written by `0x1400015b3`:

```
0x1400015b3  mov   word ptr [rsp + 0x3c], ax
0x1400015b8  fldcw word ptr [rsp + 0x3c]
```

That is an **ordinary 2-byte store of AX**, not an x87 instruction. So the memory
difference is a symptom: **AX itself differs between the two sides at that point**,
and because the divergence is between checkpoints — the registers are only compared
every 1000 instructions — the register comparison never saw it.

The two values are x87 status words:

| | value | TOP | C3 | C2 | C1 | C0 | exception flags |
|---|---|---|---|---|---|---|---|
| candidate | `0x0e7f` | 1 | 0 | 1 | 1 | 0 | `0x3f` |
| reference | `0x0c00` | 1 | 0 | 1 | 0 | 0 | `0x00` |

They agree on TOP and on C2 and C3, and differ in the **exception-flag field** — the
candidate reports all six exception flags pending where the reference reports none —
and in **C1**.

So the divergence is the **x87 status word**, which is exactly where the documented
modelling limit lives: the x87 stack is held as `double`, so precision is lost and
the flags that record it are set differently. The concrete site is
`x87_round_to_float` in `runtime/recomp_runtime.hpp`, which sets
`kX87PrecisionFlag` whenever a double does not round-trip through `float`:

```cpp
inline float x87_round_to_float(GuestContext* context, double value) {
  const auto nearest = static_cast<float>(value);
  if (static_cast<double>(nearest) == value) return nearest;
  context->x87_status_word |= kX87PrecisionFlag;
```

That accounts for one of the six flags. The other five are not yet traced.

## Fixed: the x87 control word, on both sides

Tracing what set AX showed it was not the status word at all:

```
0x140001599  fnstcw  word ptr [rsp + 0x3e]      ; read the x87 CONTROL word
0x14000159d  movzx   eax, word ptr [rsp + 0x3e]  ; EAX = control word
0x1400015b0  or      ah, 0xc                     ; rounding control := 0b11
0x1400015b3  mov     word ptr [rsp + 0x3c], ax   ; store
0x1400015b8  fldcw   word ptr [rsp + 0x3c]       ; load it back
```

So AX held the **control word**, and the two values decompose exactly:

| | stored | minus `or ah, 0xc` | control word |
|---|---|---|---|
| candidate | `0x0e7f` | `0x0e7f & ~0x0c00` | `0x027f` |
| reference | `0x0c00` | `0x0c00 & ~0x0c00` | `0x0000` |

**Both were wrong, differently.** The architectural default after `FINIT` is
`0x037f` — all exceptions masked, precision control `0b11` (extended), round to
nearest. The candidate used `0x027f`, which selects **double** precision; Unicorn
left its control word at `0x0000`, which is not a value hardware ever has. Both now
start at `0x037f`.

That is a fidelity bug in this project's own runtime, found because a guest read the
control word and the two sides disagreed — the kind of thing only a differential
comparison surfaces.

With it fixed, `x87.exe`'s first divergence moves from **checkpoint 3 to checkpoint
8**, so it resolved real divergences and a second x87 issue remains.

## Resolved: one unit in the last place, and that is the documented limit

The remaining divergence at checkpoint 8 is a **single byte** at `ESP+360`:

```
reference: ... 69 bd 9f a3 01 5c 29 40 ...
candidate: ... 68 bd 9f a3 01 5c 29 40 ...
```

Read as doubles:

| | bits | value |
|---|---|---|
| reference | `0x40295c01a39fbd69` | `12.67970000576925` |
| candidate | `0x40295c01a39fbd68` | `12.679700005769249` |

They differ by **one unit in the last place** — `1.776e-15`, a relative difference of
`1.4e-16`, which is `2^-52 * 2^3`, the spacing of doubles at that magnitude. The
mantissa's low bit is 1 on one side and 0 on the other.

**That is the documented x87 limit and not a bug.** This runtime holds the x87 stack
as `double`, with a 53-bit mantissa; the reference uses 80-bit extended with 64. A
computation whose result needs more than 53 bits rounds differently in the last
place, and nothing on arm64 fixes that without a software 80-bit float type. It is
stated in `runtime/recomp_runtime.hpp`:

> Arithmetic is modelled with `double`: on arm64 `long double` is 64-bit, so true
> 80-bit extended precision is not natively available. Values that need more than 53
> bits of mantissa can therefore differ from the original; this is a documented
> fidelity limit, not a silent substitution of single precision.

So the three floating-point fixtures diverge for the reason the documentation always
said they would, and the investigation has arrived at the documented answer by
measurement rather than by assumption.

## Consequence for `--checkpoints memory`

It cannot become a bit-exact gate as it stands, and the reason is now specific rather
than vague: for a program that uses x87, the candidate and the reference legitimately
differ in the last bit of a double, so exact memory equality is the wrong predicate.

The design that would work, and is not implemented: compare memory exactly, and when
it differs, **classify** the difference — if every differing byte lies inside an
8-byte-aligned slot whose two values are within one unit in the last place of each
other, report it as the known x87 precision class rather than as a divergence. That
keeps the gate strict for everything else, which is where a real divergence would
appear.

## Implemented: the classification, and what it shows

The comparison is now byte by byte, with a difference classified rather than simply
failed. A byte inside an aligned 8-byte slot whose two values are within one unit in
the last place of each other is the documented x87 class; anything else is a
divergence. The candidate exports the windows (`RECOMP_MEMORY_WINDOWS`) because a
digest says only *that* memory differs and classifying it needs the bytes.

`x87.exe` now passes with a named exception rather than a silent tolerance:

```
status: pass | state: True | memory: True
2 byte(s) differ by at most one unit in the last place of a double;
this is the documented x87 precision limit
```

Across the corpus:

```
memory gate passes: 18   fails: 3
  pe32_simd_convert.exe: checkpoint 12, window offset 0x84: candidate 0xa0, reference 0x80
  simd_convert.exe:      checkpoint 7,  window offset 0xcc: candidate 0xa0, reference 0x80
  vex.exe:               checkpoint 2,  window offset 0x4c: candidate 0x1,  reference 0x2d
```

`vex` is the known Unicorn AVX defect, documented in the fixture and already excluded
from the differential suite. The two `simd_convert` differences are single bytes
differing by more than one unit in the last place, so they are not the x87 class as
defined and are not yet explained.

**So `--checkpoints memory` still does not gate the verdict**, and the reason is now
narrow and named: two `simd_convert` fixtures and one known emulator defect, against
18 that agree. Making it a gate needs either those two explained or a tolerance that
is justified rather than chosen.

## The two `simd_convert` differences: MXCSR's FTZ bit

The diagnosis now reports the whole 8-byte slot, which was the first thing missing:
a single byte says nothing about whether the difference is a float, a double, an
address or an integer.

```
checkpoint 7, window offset 0xcc (8-byte slot at 0xc8):
  candidate 0x1fa020000000  reference 0x1f8020000000
```

The low 4 bytes of that slot are `0x00001fa0` against `0x00001f80`, written by

```
0x14000127c  stmxcsr dword ptr [rsp + 0x3c]
0x140001281  mov     ecx, dword ptr [rsp + 0x3c]
0x140001285  and     ecx, 0xffffffdf      ; clear bit 5
```

`stmxcsr` stores **MXCSR**, not a float. `0x1f80` is the architectural default; the
candidate's `0x1fa0` is that value **with bit 5 set**, which is **FTZ**, flush to zero.
The guest is clearing FTZ, which says it expects it set and wants it clear.

Both sides start at `0x1f80` — `kMxcsrDefaultValue` in the runtime and the explicit
write in the reference setup — and MXCSR is changed only by `ldmxcsr` and `fxrstor`.
So one of those set the bit on one side, and the next step is to trace which.

This is not a precision difference: it is a **single control bit**, and it is exactly
the kind of divergence the memory gate exists to catch. It is also the same shape as
the x87 control word found two rounds earlier — a control register read by a guest
that disagreed between the two sides.

## Not established

Which `ldmxcsr` or `fxrstor` set the FTZ bit on the candidate, and whether the
candidate or the reference is right about it.: whether they are the same precision limit at a
greater distance -- a float-to-double conversion amplifies a one-bit difference -- or
something else. Logging the *instruction* that wrote the differing byte, rather than
the byte, is what would settle it, and that is the method that found the control word. What remains is the classification rule
above, and whether any *other* program in the corpus diverges for a different reason
once the x87 class is separated out. (`0x1400010a5`), and the two
floating-point fixtures at checkpoints 12 and 7. Whether these are further x87
initialisation differences of the same kind — the status word, the tag word and the
exception flags are all plausible next candidates — or something else., and where
the other five exception flags are set. The next step is to log the x87 status word
on both sides at `0x1400015b3` and trace it back to the operation that set each bit,
rather than reading the memory it was eventually stored to., and
whether closing it means modelling the x87 tag word and the 80-bit register file.
The next step is to log the x87 state at that instruction on both sides -- the
control word, the status word and the tag word -- rather than the memory they were
written to, since the memory is only a symptom. at the same checkpoints
after the `rep` fix, so that divergence is **separate** from the `rep` counting and
is not explained by it:

```
memory agrees: 19   disagrees: 3
  pe32_simd_convert.exe: checkpoint 12 at 0x401048
  simd_convert.exe:      checkpoint 7  at 0x140001039
  x87.exe:               checkpoint 3  at 0x1400010a8
```

All three are floating-point, which is consistent with the documented x87 limit, but
that is still a hypothesis. The store log is the instrument that will settle it: it
records the **width** of every store, so an 80-bit (`tbyte`) store that differs on
the two sides would be visible directly. The next step is to diff the store logs for
`x87.exe` and look for a width-10 store rather than a width-8 one. Either

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
