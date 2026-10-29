# Architecture

Decomp Studio aims to reconstruct source and native executables from binaries, with
2D and 3D game preservation as its initial focus. The current pipeline targets a subset
of Windows PE32/x86 and PE32+/x64 binaries and can compare selected behavior under Unicorn. This document describes what the
system ACTUALLY does today, with the file that does it, and separates that from what is
planned. A reader should be able to check every claim here against the tree.

The base commit is recorded in `docs/IMPLEMENTATION_PLAN.md`. The feature branches and develop may advance independently; inspect the current tree.

## The pipeline as implemented

```
Windows PE32 / PE32+ (.exe)
  |
  |  core/detection/          format, OS and CPU identification
  v
binary::PortableExecutable            core/binary/pe.cpp
  |
  |  core/discovery/          function recovery
  v
RecoveredFunction[]                   core/discovery/function_discovery.cpp
  |
  |  core/semantics/          x86 / x86-64 -> portable IR
  v
ir::Function[]                        core/ir/ir.hpp
  |
  |  core/ir/cpp_backend       IR -> C++ against the guest runtime
  |  core/codegen/             project generation
  v
<project>/guest.cpp + recomp_runtime.cpp + build files
  |
  |  clang++ -target arm64-apple-macos11
  v
<project>/recomp-guest                 a native macOS ARM64 executable
  |
  |  core/verification/       differential comparison
  v
Verdict                               core/verification/differential_harness.hpp
```

Driven by `core/pipeline.cpp`, exposed as CLI subcommands in `apps/cli/main.cpp`:
`inspect`, `analyze`, `translate`, `build`, `run`, `verify`, `coverage`, `doctor`, `repair`,
and the whole thing as `autorecomp`.

## The guest model

`runtime/recomp_runtime.hpp` defines `GuestContext`: 16 general registers, flags,
`vector_registers[16][32]` (32 bytes, so 256-bit AVX state is representable), x87 as doubles,
`fs_base`/`gs_base`, `mxcsr`, and a flat `guest_memory` of
`kGuestAddressSpaceBytes` = 8 GiB with `guest_pointer_width` 4 for PE32 and 8 for PE32+.

Generated code is ordinary C++ that reads and writes that structure. It is not a
dispatch loop over an instruction table: each recovered function becomes a C++ function, and
`core/ir/cpp_backend.cpp` renders it. A reader can open `guest.cpp` and read the translation
of a specific function at a specific address.

### Bounded high-level reconstruction

`core/semantics/high_level_reconstruction.cpp` contains the first deliberately
narrow readable-source recognizer. It accepts only a complete function body
containing `mov eax/rax, immediate` (or `xor eax/rax, eax`) followed by `ret`,
ignoring alignment `nop`/`endbr` instructions. The generated helper is emitted
only for that exact evidence-backed shape and records the guest address as
provenance. `translate --source-style readable` selects this path; the default
`faithful` style is unchanged. All other functions continue through the
machine-level IR backend, so a readable-source count is never a claim that the
whole binary has been decompiled. The `coverage` and translation manifest report
the candidate count separately.

## What the verifier actually compares

This matters more than any other section, because it bounds every claim the project makes.

The reference is the ORIGINAL INSTRUCTIONS, executed by Unicorn. The candidate is the
generated C++. Both run and the following are compared:

| compared | where | note |
|---|---|---|
| program output | `outputs_match` | byte for byte |
| guest state at checkpoints | `checkpoints_matched` | registers, flags, x87 control/status, `mxcsr` |
| heap pages | `dirty_pages_compared` | per-page digest, **at the same checkpoint on both sides** |
| exit status | `exit_codes_match` | the two sides must AGREE; neither must be zero |
| control registers | `control_registers_match` | |

`Verdict` is one decision function: `VERIFIED`, `DIVERGED`, `REFERENCE_UNSUPPORTED`,
`CANDIDATE_UNSUPPORTED`, `INCOMPLETE`, `NOT_RUN`. Truncation is checked FIRST, so a run cut
off by the instruction ceiling can never be reported as verified.

### The limit, stated plainly

**The reference and the candidate call the SAME shim table.** A Win32 shim that is wrong in
the same way on both sides agrees with itself. `VERIFIED` therefore bounds the
**translation** -- that the machine code was lifted faithfully -- and NOT the Windows API
semantics. A program can be VERIFIED and still behave differently from a real Windows
machine. Closing that gap requires an independent oracle: a real Windows execution, or Frida
instrumentation of the original. Neither is implemented.

Two further honest caveats, both measured:

- Some programs are **nondeterministic**. `hangman_x64` picks a random word, so its output
  length varies between runs (observed 345-357 bytes), and 2 of 36 verification runs of the
  same byte-identical `hangman` binaries DIVERGED with identical output.
- The heap comparison **reports** pages written by only one side rather than judging them.

## Analysis providers

### Ghidra -- implemented

`apps/cli/ghidra_run.cpp` invokes Ghidra's `analyzeHeadless` with a script directory;
`apps/cli/ghidra_import.cpp` parses the `ExportFunctions` output into records that carry the
binary's SHA-256, the function address, and **provenance**: the record distinguishes a
function Ghidra reported from one this project inferred, and an export whose provenance
cannot be established is marked unverified rather than trusted.

Analysis runs as an EXTERNAL PROCESS. That is both a technical boundary (Ghidra is a JVM
application) and a licensing one (see `docs/UPSTREAM_COMPONENTS.md`).

### rev.ng -- adapter only

`revng-run` invokes rev.ng externally and preserves artifacts and hashes. It has been
tested with a stand-in; actual rev.ng output has not been verified on this host.
It is not integrated into the compiled source pipeline.

### Remill -- partially implemented

Remill's instruction semantics are ADAPTED, with attribution, for a specific set of
instructions (`MOVLHPS`, `MOVHLPS`, `AAS`, `PINSRW`, `PEXTRW`, `VPBROADCASTB` and others),
recorded with exact upstream commits in `THIRD_PARTY_NOTICES.md`. Remill is not built or
linked as a library.

### PCRecomp -- partially implemented

PCRecomp's Ghidra scripts are used by `ghidra-run`. Optional tests build its pinned
translator and runtime, including a limited stateless CRT bridge and an adapted indexed
bitmap implementation. The production `autorecomp` runtime does not use PCRecomp as a
general provider; guest memory and callback contracts remain to be bridged.

## The runtime

`runtime/recomp_runtime.cpp` implements the Windows surface the corpus asks for: CRT,
kernel32 file and heap, user32 window and message handling (ANSI and wide), and
`__stdio_common_vsscanf`/`vsprintf`. Shims are registered in TWO places -- `kShims` and
`kWin32ImportAbiTable` -- because the import census reads the ABI table to decide whether a
symbol is implemented.

An unimplemented import is REFUSED BY NAME, at the instruction that called it, with the
register state. Other imports may have partial or stub behavior and must be assessed individually.
The `init_common_controls` shim is documented at its definition: the real function loads a control
library so later `CreateWindowEx` calls can name a control class, and in a process with no
window manager that load has no observable effect, so returning success is what the call
means rather than a fabrication.

## What is deliberately NOT here

- **No game-specific code in the core.** No address, string or behaviour of any particular
  game appears in `core/`, `runtime/` or `apps/`.
- **No claim that emulation is recompilation.** The Unicorn reference is labelled a
  reference everywhere it appears.
- **No claim that a program is verified because it runs.** `verified()` reads the verdict,
  and the verdict reads the comparisons.
