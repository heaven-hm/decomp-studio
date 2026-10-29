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
- **It reconciles addresses only.** The provider record also carries `calling_convention`,
  `flags`, `body_bytes` and `references`; those are **not yet compared**. Calling conventions
  are the next fact worth reconciling, and the rule for them is already fixed: a convention
  is not changed without an ABI test.
- **It has no rev.ng input**: the external-process `revng-run` adapter preserves a raw
  artifact, but parsing and reconciling that artifact are not implemented.
