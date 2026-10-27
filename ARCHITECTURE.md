# Architecture

Recomp Studio is a static recompiler: it reads a guest executable, recovers its
functions, translates every instruction to architecture-neutral C++, and
compiles that C++ for a chosen host target. The guest keeps its own CPU state,
its own flat address space and its own operating-system shims, so the translated
code runs as a normal native process.

```
  input image                translation core                 host output
  ───────────                ────────────────                 ───────────
  PE32 / PE32+  ──►  parse ──►  discover functions ──►  lift to C++  ──►  clang++  ──►  arm64 / x86_64
                                   (Capstone)          (per arch)                    linux / wasm
                                        │                    │
                                        ▼                    ▼
                                 differential verify ──►  guest runtime (memory, CPU, dispatch, Win32)
                                      (Unicorn)
```

## Layers and extension points

| Layer | Header | Responsibility | To extend |
|-------|--------|----------------|-----------|
| Binary format | `core/binary/pe.hpp` | Parse the executable, sections, imports, exports, relocations, TLS; build a loadable image | Add a sibling such as `elf.hpp` producing the same facts |
| Discovery | `core/discovery/function_discovery.hpp` | Decode instructions, recover function entries, basic blocks and tail calls | Swap the decoder (Zydis, Ghidra) behind the same interface |
| Lifting | `core/semantics/x86_64_lifter.hpp` | Emit C++ for each instruction against the runtime helpers; the same emitter serves PE32 and PE32+ (decode mode and pointer width come from the image) | Add `aarch64_lifter`, `mips_lifter`, ... emitting the same runtime calls |
| Code generation | `core/codegen/project_generator.hpp` | Emit `guest.cpp`, copy the runtime, embed the image | Add per-function output files or a single-file patch mode |
| Pipeline | `core/pipeline.hpp` | Orchestrate translate / build / run and the manifest | Add targets; the target name maps to an LLVM triple |
| Runtime | `runtime/recomp_runtime.hpp` | Guest memory, CPU context, dispatch, import thunks, Win32 shims | Add shim families (user32, ddraw, d3d) and other guest ABIs |
| Verification | `core/verification/differential_harness.hpp` | Execute the original code under Unicorn and compare outputs and instruction traces | Add per-function differential testing and seeded inputs |
| Harness | `core/harness/repair_harness.hpp` | Autonomous translate → build → verify → diagnose → repair loop | Add agent adapters and bounded patch acceptance |

The four axes — format, architecture, target, runtime — are independent. A new
architecture supplies a lifter and a runtime; a new target supplies a triple and
a platform runtime; neither requires touching the other.

## Execution model

Each recovered guest function becomes one C++ function, `guest_function_<addr>`,
taking a `GuestContext*`. Guest registers, flags and vector state live in the
context; guest memory is a single flat mapping addressed by guest virtual
address. This mirrors N64Recomp (one C function per guest function) and
igi-recomp (registers in a context, memory as a flat array).

- **Direct calls** become native calls. The guest return address is pushed so the
  guest stack stays faithful; the callee's `ret` pops it and returns.
- **Indirect calls and jumps** go through a dispatch table keyed by guest address
  (import thunks included). Unknown targets fail loudly instead of jumping into
  host memory.
- **Flags** are computed with the exact x86 rules for every width. `add` sets
  carry, overflow, auxiliary, zero, sign and parity; shifts, rotates, `mul`,
  `div`, `inc`/`dec` and `neg` follow their own rules.
- **Partial registers** are modelled precisely: 32-bit writes zero-extend, 16-bit
  and 8-bit writes merge, and `ah`/`ch`/`dh`/`bh` address bits 8-15.
- **Guest pointer width** is carried by the runtime (`guest_pointer_width`):
  stack pushes/pops, call/return, and effective-address computation all adapt, so
  a PE32 guest wraps at 2^32 while a PE32+ guest does not.
- **Import calling convention** is data, not code: `runtime/win32_abi.hpp` records
  each shim's argument count and whether it cleans the stack, and the runtime and
  the Unicorn reference both consume that table. On x86 the runtime emulates the
  `call`→`ret`/`ret n` sequence so the guest stack matches hardware.
- **Imports** are bound by writing a per-import thunk address into each IAT slot,
  exactly as a loader would, so both direct `call [iat]` and a pointer loaded and
  called later resolve to the shim.

## Configuration

A project is described by a small configuration file (see
`tests/fixtures/apps/recomp.toml` for a worked example):

```toml
name = "arith"
target = "macos-arm64"
entry_point_rva = 0x1c30
stack_top = 0x170000000
heap_base = 0x168000000

stub_function = [0x140001000]              # replace with a returning no-op
native_override = ["0x140001530: my_impl"]  # HLE: hand-written host function
instruction_patch = ["0x140001001: b9 f4 ff ff ff"]
extra_sources = ["src/my_impl.cpp"]
compile_flags = ["-O2"]
```

The effective configuration is written into the generated project as
`recomp-config.toml`, so `build` reproduces the exact same settings.

## Advanced roadmap

The following capabilities are the ones the mature recompilation projects
converge on, and where this tool will grow next:

1. **Backward flag liveness** — compute only the flags a later instruction reads
   (igi-recomp does this). Large speed-up on flag-heavy integer code.
2. **Jump-table recovery** — recognise `jmp [table + index*8]` with its bounds
   check and emit a `switch` with a dispatch fallback, instead of always doing
   dynamic dispatch (igi-recomp, N64Recomp).
3. **x87 and full SSE/AVX** — the x87 stack is modelled in the context but not
   yet lifted; 80-bit arithmetic must stay exact rather than degrading to doubles.
4. **High-level emulation and native replacement** — already supported by address;
   the next step is hash-guarded replacement (apply only when the guest bytes
   match a known SHA-256), as igi-recomp does for CRT routines.
5. **Function hooks** — emit instrumentation before and after named functions
   (N64Recomp's `patches.hook`).
6. **Relocatable overlays and reloc macros** — support images loaded at a
   runtime-chosen base by emitting relocation macros the runtime applies.
7. **Runtime interpreter fallback** — for indirect targets that were never
   discovered, execute them in an embedded x86 interpreter sharing the context.
8. **Per-function output files and single-file patch mode** — faster incremental
   builds and link-time function overriding (N64Recomp).
9. **More targets** — Linux x86-64/ARM64 and wasm32 triples are already wired
   through the target table; they need their own platform runtimes.
10. **More shim families** — user32, gdi32, ddraw, d3d8/9 for graphical titles.
11. **A real-title profile** — the Project IGI profile from the brief, driving the
    import census, function inventory and readiness reports.

## Verification

Verification is first-class. The reference side executes the original x86-64
machine code under Unicorn with the same shim semantics as the runtime; the
candidate side runs the compiled host binary. Two comparisons are performed:

- **Program level** — the bytes written to standard output must match exactly.
- **Instruction trace level** — the sequence of executed guest addresses must
  match; the first divergence identifies the responsible instruction.

The repair harness runs this loop, writes a structured report per iteration and,
when configured with an external agent, hands the diagnosis to it and rebuilds.
It never marks a translation verified merely because it compiled.
