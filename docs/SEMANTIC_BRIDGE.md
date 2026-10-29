# Semantic bridge

How facts from different analysis providers are combined -- and, more importantly, how they
are **not** combined. The implementation is `apps/cli/ghidra_reconcile.cpp`; the test that
tries to defeat it is `tests/compat/ghidra_reconcile_test.py`.

## The problem this exists for

The Ghidra import emits `"binary_export_association": "unverified"`. That is honest and it
is a real limitation: **nothing inside an `ExportFunctions` file proves which binary produced
it.** A record whose association is unverified cannot be allowed to change what the
translator does, because a wrong association would attribute one program's function
boundaries to another and every downstream fact would inherit the error.

Comparison can expose conflicts, but matching addresses do not establish which binary an
export came from. Preserve conflicts and require separate provenance for binary identity.

## What is reconciled

This project's **own** function discovery is the independent source. It is derived from the
binary by a different method -- Capstone decoding, seeded from the entry point, relocations,
exception data and jump tables -- and shares no code with Ghidra. Two independent derivations
of the same binary that agree would be corroboration; this tool cannot establish that premise.

```
binary ──┬─> recomp-studio discovery ──> local addresses     ─┐
         │                                                    ├─> reconcile ─> states
         └─> Ghidra (external) ──> export ──> provider addrs ─┘
```

## The states, and what each means

| state | meaning | confidence |
|---|---|---|
| `agreed` | both records report this address | `matching-address-only` |
| `provider-only` | only the provider reports it | `single-provider` |
| `local-only` | only this project reports it | `single-provider` |

**Nothing is merged.** A `provider-only` address is not added to the local set and a
`local-only` address is not discarded: they are reported side by side with the source named,
because the reconciliation rule is that incompatible hypotheses are preserved. Collapsing
them into "N functions recovered" would launder one source's guess into a number that looks
corroborated.

## The association verdict

| verdict | when |
|---|---|
| `unverified` | every record: address overlap alone cannot prove binary identity |

The separate `address_agreement` field reports `complete`, `partial`, or `none`.
Exit zero means every reported provider address appeared in local discovery; it does not
verify identity, completeness, function boundaries or behavior.

## Two bugs the test found in the implementation

Recorded because both are ways a reconciliation layer lies while looking correct:

1. **The parser accepted only one writer's spacing.** It required `"address":"` exactly, so a
   record written with a space after the colon parsed as having **no functions at all** --
   and full agreement was reported as a **contradiction**. A parser that accepts one writer's
   formatting is not reading JSON. It now uses the vendored JSON for Modern C++ parser,
   reads addresses only from the functions array, and rejects malformed and duplicate addresses.
2. **The exit rule treated any agreement as success.** It was
   `agreed.empty() && !provider.empty()`, so a record that agreed on 36 functions and
   invented a 37th exited **zero**. Partial agreement is still disagreement about the rest,
   and the exit status is what a caller acts on.

Both were found by driving the tool with records that were deliberately right, deliberately
wrong, and deliberately partial -- not by reading the code. A reconciliation layer that has
never been shown a contradiction has not been shown to detect one.

## What this does NOT do

- **It does not change the translator.** No output of the reconciler feeds back into code
  generation. Using an unverified provider to change what is emitted is exactly what the
  `unverified` marking exists to prevent.
- **It reports calling conventions but does not compare them against the provider's yet.**
  The convention is derived from the function's own `ret` instruction -- the ABI signal the
  machine actually carries: `ret` returns with no stack adjustment (cdecl), `ret N` pops N
  bytes (stdcall). It is not a guess about the source; it is what the epilogue does, and the
  lifter already emits it (`return_from_guest_function(context, N)` in
  `core/semantics/x86_64_lifter.cpp`). A function with no `ret` at all -- one that ends in a
  `jmp`, or a thunk -- is reported `unknown` rather than defaulted to cdecl.
  The provider's `calling_convention` field is **not yet read**, so the two are not compared.
- **`flags`, `body_bytes` and `references` are not compared either.**
- **It has no rev.ng input.** The external-process `revng-run` adapter preserves a raw rev.ng
  artifact, but parsing and reconciling that artifact are not implemented -- so rev.ng is not
  yet a second provider here. When it is, the mechanism is already fixed: per
  `docs/UPSTREAM_COMPONENTS.md` rev.ng is GPLv2, so it must stay an external process.