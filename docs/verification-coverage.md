# Verification coverage: what the memory digest does and does not cover

Measured 2026-10-28 on `feature/x86-x64-arm64-mvp`. Every number here was established
from the code and from runs, not estimated.

## What is compared today

`guest_memory_digest` (`runtime/recomp_runtime.cpp`) hashes exactly two contiguous ranges:

| range | length |
|---|---|
| `[RSP, RSP + 0x1000)` — the live stack, from the stack pointer upward | 4 KiB |
| `[image_base, image_base + 0x10000)` — the image's writable area | 64 KiB |

**68 KiB per checkpoint.** Against the 8 GiB guest mapping that is 0.0008%; against the
live writable set (128 MiB heap + 1 MiB stack + image) it is 0.05%.

Two things this is *not*, both worth stating because they are easy to assume:

- **It is not sampled.** `digest_bytes` is a full byte-by-byte FNV-1a loop, so the
  probability of missing a changed byte inside a window is **zero**. The
  `kMemoryWindowSampleLimit` constant gates only the *diagnostic byte dump*, not the
  digest.
- **It is not the whole writable set.** The heap is `[heap_base, stack_top)` = **128 MiB**
  and is **0% covered** — it is disjoint from both windows.

## The gap, measured

Using the runtime's own store log (`RECOMP_STORE_LOG`):

| fixture | stores to the heap | heap coverage |
|---|---|---|
| `heap.exe` | **74.0%** of 4,258 stores | 0% |
| the four non-allocating fixtures | 0% | n/a (100% stack) |

Even within the stack, **0–23%** of stores fall outside every window the digest takes.

A buffer written and never printed is therefore **not compared**. That is precisely the
"silent non-output heap corruption" a verification gate is supposed to catch, and today
it would pass.

Other regions with no coverage: the TEB/PEB, the environment blocks, the command line,
and the low page. No file is ever mapped into guest memory — the only `mmap` is the
single anonymous 8 GiB mapping.

## The x87 precision tolerance has a boundary

A byte inside an aligned 8-byte slot whose two doubles are within one ULP is classified
as the documented x87 precision limit rather than a divergence. That classification
**only exists for the first 512 checkpoints**: past 512,000 guest instructions no window
is captured to classify against, so an x87 difference becomes a hard divergence. The
counter `x87_precision_differences` counts **bytes**, not slots.

## A fix that was tried and does not work

The obvious smallest change is a dirty-page set: mark each 4 KiB page a store touches and
fold those pages into the digest. It was implemented, measured, and **reverted** — it made
**every fixture diverge at checkpoint 0**, before either side had run.

The cost was fine; the *set* is the problem. A fixed window hashes the same addresses on
both sides by construction. A dirty set is a function of which instructions have executed
so far, and the two sides reach "checkpoint 0" having executed a different number.
Hashing it compares the harness's own checkpoint arithmetic rather than the program's
memory.

What would work instead:

1. Agree the checkpoint instruction index on both sides first, then hash a dirty set — a
   change to the checkpoint contract, not to the digest; or
2. Compare only the pages **both** sides marked, and report the set difference
   separately. Cheaper, and it keeps a one-sided write attributable instead of collapsing
   it into an opaque digest mismatch.

## What is not established

- Whether any *real* application is affected: none currently runs to completion, so the
  74% figure comes from `tests/fixtures/apps/bin/heap.exe`.
- The measured cost of either proposed fix; neither is prototyped.
