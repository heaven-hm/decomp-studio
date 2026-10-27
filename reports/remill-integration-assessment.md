# Remill integration — inspection record and assessment

Inspection performed before any integration, as the integration rules require.
Nothing here is copied from Remill; this records what was found and what adopting
it would take.

## 1. Identity and licence

| Property | Value |
|---|---|
| Project | lifting-bits/remill |
| Revision inspected | `56918a8c2554088e93389e97d292f4035286506c`, 2026-08-20 |
| Licence | **Apache-2.0** |
| Local checkout | `research/upstream/remill` (gitignored) |
| Size | 12 MB, 119 C++ sources |

The licence is Apache-2.0, the same as this project's core, so there is no
licence conflict. Attribution and the notice file must be carried if source is
vendored.

## 2. What it provides

Remill lifts machine code to LLVM IR. The structure the integration plan names:

- `include/remill/Arch/` — the architecture interface, context and instruction
  types (`Arch.h`, `ArchBase.h`, `Context.h`, `Instruction.h`).
- `lib/Arch/X86/Semantics/` — the x86/x64 semantics, by instruction family:
  `BINARY.cpp`, `SSE.cpp` (2,349 lines), `AVX.cpp`, `FMA.cpp`, `MMX.cpp`,
  `FLAGOP.cpp`, `CONVERT.cpp`, `DECIMAL.cpp`, `IO.cpp`, `INTERRUPT.cpp`, and more.
- `lib/BC/` — the LLVM bitcode layer: `InstructionLifter.cpp`, `IntrinsicTable.cpp`,
  `Optimizer.cpp`, `PcodeCFG.cpp`, `SleighLifter.cpp`, `TraceLifter.cpp`.

Semantics are written as templates over a typed value abstraction and bound to
instructions by name:

```cpp
template <typename D, typename S1, typename S2>
DEF_SEM(SHUFPS, D dst, S1 src1, S2 src2, I8 src3) {
  auto dst_vec = UClearV32(UReadV32(src1));
  ...
  UWriteV32(dst, dst_vec);
  return memory;
}

DEF_ISEL(SHUFPS_XMMps_XMMps_IMMb) = SHUFPS<V128W, V128, V128>;
DEF_ISEL(SHUFPS_XMMps_MEMps_IMMb) = SHUFPS<V128W, V128, MV128>;
```

That is a genuinely better shape than this project's lifter for the families it
covers: `SHUFPS` is one template and two bindings, where this project's lifter
emits C++ text per mnemonic.

## 3. Dependencies, and the decisive one

| Dependency | State here | Note |
|---|---|---|
| LLVM | **present** (23.1.3, Homebrew) | `find_package(LLVM CONFIG REQUIRED)`; Remill keys its install path on the LLVM major version |
| Intel XED | **missing** | not a Homebrew formula here; the `third_party/` submodule is not vendored in the checkout |
| Remill itself | **missing** | not built or installed |

**The decisive integration fact: Remill keys its semantics on XED instruction
names (`DEF_ISEL(SHUFPS_XMMps_XMMps_IMMb)`), and this project decodes with
Capstone.** Capstone reports `shufps`; Remill's table is indexed by XED's
`SHUFPS_XMMps_XMMps_IMMb`. So integration is not a drop-in — it requires either

1. adopting XED as the decoder for the Remill path, which changes
   `core/discovery/` and the lifter's input, or
2. maintaining a Capstone-mnemonic-and-operand-form → XED-isel-name mapping,
   which is a second table that must stay correct as both projects move.

Option 1 is the honest one and is what Remill is designed around. It is also a
change to the decoder that every existing fixture and both IGI executables
currently pass through, so it needs the equivalence evidence the plan already
requires before the Capstone path is retired.

`doctor` now reports all three of these states, so the dependency is visible and
checkable rather than discovered halfway through a build:

```
$ recomp-studio doctor
llvm:    present  (optional; required by the LLVM IR backend and by Remill)
xed:     missing  (optional; Remill keys its x86 semantics on XED instruction names)
remill:  missing  (optional; Apache-2.0 semantic library, not yet integrated)
```

Presence is established from the artifact each component installs, never from a
command name. That is not pedantry: macOS ships a program called `xed` in
`/usr/bin`, and it is a text editor. The first version of this probe reported
Intel XED as present because of it, and was corrected.

## 4. Assessment

Adopting Remill is a multi-session piece of work, not an afternoon's integration:

1. build and install XED (Apache-2.0) and Remill against LLVM 23;
2. add `adapters/remill/` and a build option, keeping the Capstone lifter as the
   default until parity is demonstrated;
3. decide the decoder question in §3, and carry the equivalence evidence;
4. lift to LLVM IR rather than C++ text, which is the same boundary the
   architecture-neutral IR task needs;
5. keep the existing C++ backend operational throughout, per the plan.

The order matters: **the IR boundary is the prerequisite**. Remill produces LLVM
IR; this project produces C++ text. Without an intermediate representation
between the lifter and the backend, adopting Remill means replacing the backend
at the same time as the frontend, and there would be no point at which both are
known to agree.

## 5. What was done instead, and why

The verification foundation was completed first, because it is what makes any of
this checkable: the runtime and the differential reference now share one shim
implementation and one startup state, and a mutation test demonstrates that the
comparison detects a real behavioural change (`c14ef07`). Without that, an LLVM
backend could not be shown to be equivalent to anything.
