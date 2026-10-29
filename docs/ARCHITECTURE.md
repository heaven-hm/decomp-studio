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

### Hybrid source: three classes, one delivered tree

Every recovered function is classified and the classification travels with
the emitted source, from the shared `LiftedProgram` through
`GeneratedProject`, `TranslateReport`, `recomp-source-map.json`, and the
translation manifest. There are three classes plus an explicit override:

| class | meaning | in `guest.cpp` |
|---|---|---|
| `high-level verified` | whole-body recognizer matched; readable helper with provenance header | emitted typed helper + guest-context wrapper |
| `low-level fallback` | function exists but no recognizer matched | machine-level IR translation |
| `unresolved` | function body could not be lifted at all | diagnostic, never silently dropped |
| `policy override` | explicitly configured, recorded as such | config-driven |

`core/semantics/high_level_reconstruction.cpp` contains the recognizers. Each
one accepts a COMPLETE function body -- no extra instructions, no flags effects
outside the recognized shape -- and emits evidence backed by the decoded
instructions:

- `constant-return`: `mov eax/rax, imm` + `ret` (width 4/8 from the register).
- `stack-argument-return`: `mov eax, dword ptr [esp + 4]` + `ret`.
- `register-argument-return`: `mov eax, ecx` / `mov rax, rcx` + `ret`.

Alignment `nop`/`endbr` instructions are ignorable; anything else makes the
body ineligible. Names and types in the rendered helper are deliberately
generic (`reconstructed_0x401000`), never invented symbol names presented as
recovered facts. The provenance header states the class, recognizer, machine
evidence, and confidence.

`translate --source-mode hybrid` enables the recognizers; the default
`--source-mode low-level` keeps the previous faithful output and reports zero
high-level functions. `--source-mode hybrid --source-quality human-readable`
is a fail-closed gate: translation refuses to write any file unless the census
shows `unresolved == 0` and `high_level_verified > 0`, and the refusal reports
the measured census. A readable percentage is therefore always a measured
claim about the delivered tree, never an aspiration.

Provenance files written next to `guest.cpp`:

- `recomp-source-map.json` -- per function: address, classification,
  recognizer or blocker, evidence, instruction and byte counts, plus the
  census (`total_functions`, `high_level_verified`, `low_level_fallback`,
  `unresolved`, `policy_override`, `high_level_percent`; the percentage is
  capped at 99.99 until every function is verified).
- `recomp-source-manifest.json` -- every generated file with SHA-256 and
  size. Both translate and build use the same `LiftedProgram`: the delivered
  source IS the compiled source.
- `recomp-build-manifest.json` (written by `build`) -- executable path,
  SHA-256, size, compiler, target, command, and the source hashes that were
  verified before compilation. `build` fails closed if any manifest hash is
  missing or does not match the file on disk.
- `recomp-manifest.json` -- image identity: input SHA-256, architecture,
  function and import counts, entry point, unsupported mnemonics.

### Target matrix, stated honestly

| guest | host | status |
|---|---|---|
| Windows x86 (PE32) | macOS ARM64 (native process) | proven: the default `native` target; this is the path the end-to-end tests execute |
| Windows x86 (PE32) | Windows x86 process | unsupported: no Windows host or Wine provider in this tree |
| Windows x86 (PE32) | Windows x64 process | unsupported: same blocker |
| Windows x64 (PE32+) | macOS ARM64 | lifting and verification exist; the Windows-native target rows stay unsupported |
| Windows x64 (PE32+) | Windows x64 process | unsupported: no Windows host provider |

The runtime is POSIX-only and no Wine integration ships in this tree, so a
request for a Windows native target is refused with the exact blocker rather
than approximated. macOS ARM64 execution of translated x86/x64 guest code is
the proven path because the generated C++ is ordinary host code and the
verifier runs it as a native process.

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
