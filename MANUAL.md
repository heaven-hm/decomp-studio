# Recomp Studio — Manual

Everything you can do with the `recomp-studio` CLI, with a worked example for
every command and an exact statement of which operating systems and processor
architectures are supported today.

- [1. Concepts](#1-concepts)
- [2. Supported platforms](#2-supported-platforms)
- [3. Install and build](#3-install-and-build)
- [4. Command reference](#4-command-reference)
- [5. End-to-end walkthroughs](#5-end-to-end-walkthroughs)
- [6. Configuration file](#6-configuration-file)
- [7. Verification and the repair harness](#7-verification-and-the-repair-harness)
- [8. Writing your own test fixture](#8-writing-your-own-test-fixture)
- [9. Diagnostics and troubleshooting](#9-diagnostics-and-troubleshooting)
- [10. Limitations](#10-limitations)

---

## 1. Concepts

Recomp Studio turns a **guest** executable into a native **host** program.

| Term | Meaning |
| --- | --- |
| Guest | The input program you supply (today: a Windows x86-64 PE32+). |
| Host | The machine and operating system the recompiled binary runs on. |
| Target | A named host platform + CPU combination, e.g. `macos-arm64`. |
| Project | The generated directory: `guest.cpp`, the runtime, and a manifest. |

The pipeline is:

```
inspect → analyze → translate → build → run → verify
```

`translate` is deterministic and offline. `verify` executes the *original*
x86-64 code under Unicorn with the same Win32 shims as the runtime and compares
its output, and its instruction trace, with the compiled host binary.

---

## 2. Supported platforms

### 2.1 Guest (input) platforms

| Guest OS | Container | CPU | Lifting | Notes |
| --- | --- | --- | --- | --- |
| Windows | PE32+ | x86-64 | **Supported, verified** | `CS_MODE_64` decode, 64-bit pointer width. |
| Windows | PE32 | IA-32 (x86) | **Supported, verified** | `CS_MODE_32` decode, 32-bit pointer width and address wrapping, stdcall import stack cleanup. |
| Any other | ELF / Mach-O / ROM | any | Not implemented | Kept behind the format layer for future work. |

Both guest architectures share one translation core. The decoder mode, the
guest pointer width and the emulated import calling convention are selected from
the PE header and the per-import ABI table (`runtime/win32_abi.hpp`), so a
32-bit stdcall callee pops its arguments exactly as on real hardware.

### 2.2 Host (output) platforms

| Host OS | CPU | Target name | Toolchain needed | Status |
| --- | --- | --- | --- | --- |
| macOS | arm64 | `macos-arm64` (or `native`) | Xcode command-line tools | **Supported — verified end to end** |
| macOS | x86-64 | `macos-x86_64` | Xcode command-line tools | **Supported — verified** (runs under Rosetta 2 on Apple Silicon) |
| Linux | arm64 | `linux-arm64` | Linux cross sysroot + `clang++` | Target wired; translation works, build needs a sysroot |
| Linux | x86-64 | `linux-x86_64` | Linux cross sysroot + `clang++` | Target wired; translation works, build needs a sysroot |
| Any (browser) | wasm32 | `wasm` | wasi-sdk / `wasm-ld` | Target wired; build needs a wasm sysroot |

Run `recomp-studio doctor` to see what your machine supports.

The generated runtime is POSIX C++ (it uses `mmap`, `read`/`write`,
`clock_gettime`), so the Linux targets only need a Linux libc and headers linked
against them; the wasm target additionally needs the Win32 shim layer adapted
(no file descriptors).

---

## 3. Install and build

### 3.1 Prerequisites

```sh
brew install cmake ninja capstone unicorn mingw-w64
```

| Tool | Required | Purpose |
| --- | --- | --- |
| C++20 compiler (Apple clang) | yes | Builds the studio and generated projects |
| CMake ≥ 3.26, Ninja | yes | Build system |
| Capstone | yes | x86-64 decoding |
| Unicorn | optional | Differential verification backend (GPL-2.0) |
| mingw-w64 | optional | Builds the Windows test fixtures |

### 3.2 Build the studio

```sh
./scripts/build.sh
# equivalent to:
#   cmake -S . -B build -G Ninja
#   cmake --build build
```

Build without the verification backend:

```sh
cmake -S . -B build -G Ninja -DRECOMP_ENABLE_UNICORN=OFF
cmake --build build
```

### 3.3 Run the test suite

```sh
./scripts/test.sh
```

Expected tail:

```
100% tests passed, 0 tests failed out of 2
```

---

## 4. Command reference

Every command supports `--json` for machine-readable output. `translate`,
`build` and `repair` accept `--config <file>`.

### 4.1 `doctor`

```sh
build/recomp-studio doctor
build/recomp-studio doctor --json
```

```
host:    macos
target:  macos-arm64 (native)
input:   PE32+ x86_64
runtime: present (/path/to/recomp-studio/runtime)
```

### 4.2 `inspect`

Parse the executable and report structure, imports and hashes.

```sh
build/recomp-studio inspect tests/fixtures/apps/bin/tictactoe.exe
build/recomp-studio inspect tests/fixtures/apps/bin/tictactoe.exe --json
```

```
format:      PE32+ (x86_64)
entry point: 0x000018a0
image base:  0x140000000
sha256:      17f7b36b...
sections:    4
imports:     3
  kernel32.dll!ExitProcess
  kernel32.dll!GetStdHandle
  kernel32.dll!WriteFile
```

### 4.3 `analyze`

Recover functions and count instructions.

```sh
build/recomp-studio analyze tests/fixtures/apps/bin/snake.exe
```

```
architecture: x86_64
functions:    4
instructions: 552
```

### 4.4 `coverage`

Classify every recovered instruction and report the classes the lifter does not
implement. `translate` stops at the *first* unsupported instruction, so for a
real application this is the command that tells you the true size of the gap
instead of one line of it.

```sh
build/recomp-studio coverage tests/fixtures/apps/bin/arith.exe
```

```
architecture:   x86_64
functions:      5
instructions:   688
lifted:         688 (100.00%)
unsupported:    0
coverage:       complete — every recovered instruction lifts
```

A program the lifter cannot translate reports every unsupported class, most
frequent first, with the first site and the function it belongs to:

```sh
build/recomp-studio coverage tests/fixtures/apps/bin/unsupported_instruction.exe
```

```
architecture:   x86_64
functions:      2
instructions:   206
lifted:         204 (99.03%)
unsupported:    2
classes:        2 distinct unsupported instruction classes

occurrences  mnemonic                    first site
1            fld1                        0x01400010ce in 0x0140001000
1            fstp                        0x01400010d0 in 0x0140001000
```

On a real Windows binary the same command produces the work list directly. Here
is a 1 MB PE32+ console program (`plink.exe`, SHA-256 `969f3687…`):

```sh
build/recomp-studio coverage plink.exe
```

```
architecture:   x86_64
functions:      2208
instructions:   164668
lifted:         162631 (98.76%)
unsupported:    2037
classes:        82 distinct unsupported instruction classes

occurrences  mnemonic                    first site
234          pmuludq                     0x0140072408 in 0x01400721e0
160          psrad                       0x0140072433 in 0x01400721e0
132          aesenc                      0x014007d290 in 0x014007d260
...
```

`--json` emits the same facts for automation: `total_instructions`,
`lifted_instructions`, `unsupported_instructions`, `coverage_percent`,
`unsupported_class_count`, and an `unsupported` array whose entries carry
`mnemonic`, `occurrences`, `first_address`, `first_function` and the lifter's
`reason`.

The census never decides whether a translation is accepted — `translate` still
fails closed on the first unsupported instruction. The regression suite
cross-checks the two against each other: translation must succeed exactly when
the census reports 100% coverage, so a census that over-reported would
contradict a successful translation and one that under-reported would contradict
a failed one.

### 4.5 `functions`

List recovered function candidates with their size.

```sh
build/recomp-studio functions tests/fixtures/apps/bin/arith.exe
```

```
0x140001000  instructions=29 blocks=1
0x140001080  instructions=268 blocks=28
...
```

### 4.6 `cfg`

Export one function's control-flow graph as Graphviz DOT.

```sh
build/recomp-studio cfg tests/fixtures/apps/bin/arith.exe --address 0x140001080
build/recomp-studio cfg tests/fixtures/apps/bin/arith.exe --address 0x140001080 --json
```

Render it:

```sh
build/recomp-studio cfg tests/fixtures/apps/bin/arith.exe --address 0x140001080 \
  | dot -Tpng -o cfg.png
```

### 4.7 `translate`

Generate a host project from the guest executable. This is the core step.

```sh
build/recomp-studio translate <image> --output <dir> [--target <target>] [--config <file>] [--json]
```

```sh
build/recomp-studio translate tests/fixtures/apps/bin/arith.exe \
    --target macos-arm64 --output out/arith
```

```
translated 5 functions, 3 imports
project:  out/arith
source:   sha256=36853847e207afef...
```

The project contains `guest.cpp`, `recomp_runtime.hpp/.cpp`,
`recomp-config.toml` and `recomp-manifest.json`.

### 4.8 `build`

Compile the generated project into a native executable.

```sh
build/recomp-studio build out/arith
```

```
built out/arith/recomp-guest
```

### 4.9 `run`

Execute the generated binary.

```sh
build/recomp-studio run out/arith
```

### 4.10 `verify`

Compare the generated binary against the original x86-64 code (Unicorn
reference): output bytes and instruction trace.

```sh
build/recomp-studio verify out/arith
build/recomp-studio verify out/arith --json
```

```
executed instructions (reference): 177340
reference output: 172 bytes
candidate output: 172 bytes
VERIFY: PASS (identical output)
```

Exit code is `0` on PASS, `1` on FAIL.

### 4.11 `repair`

The autonomous loop: translate, build, verify, localise the first divergence and
write a per-iteration report.

```sh
build/recomp-studio repair <image> --output <dir> [--budget N] [--agent "<command>"] [--json]
```

```sh
build/recomp-studio repair tests/fixtures/apps/bin/snake.exe --output out/snake
```

```
repair harness: 1 iteration(s)
  [1] functions=4 imports=3 built=yes verified=yes
      candidate output is byte-identical to the reference execution
RESULT: VERIFIED
report: out/snake/reports/harness
```

On a mismatch it names the first divergent instruction and the unsupported
mnemonics it saw, e.g.:

```
  [1] functions=670 imports=153 built=yes verified=no
      first control-flow divergence at step 0 ...; unsupported mnemonics: addsd, bts, vpxor, ...
```

### 4.12 `report`

Print the generated project manifest.

```sh
build/recomp-studio report out/arith
```

### 4.13 `examples`

```sh
build/recomp-studio examples list
```

---

## 5. End-to-end walkthroughs

### 5.1 macOS ARM64 (primary, verified)

```sh
./scripts/build.sh
cd tests/fixtures/apps && ./build.sh && cd ../../..
build/recomp-studio translate tests/fixtures/apps/bin/tictactoe.exe \
    --target macos-arm64 --output out/tictactoe
build/recomp-studio build out/tictactoe
build/recomp-studio run   out/tictactoe
build/recomp-studio verify out/tictactoe
```

`file out/tictactoe/recomp-guest` → `Mach-O 64-bit executable arm64`.

### 5.2 macOS x86-64 (verified; runs under Rosetta on Apple Silicon)

```sh
build/recomp-studio translate tests/fixtures/apps/bin/arith.exe \
    --target macos-x86_64 --output out/arith-x86
build/recomp-studio build  out/arith-x86
file out/arith-x86/recomp-guest        # Mach-O 64-bit executable x86_64
build/recomp-studio verify out/arith-x86
```

### 5.3 Linux ARM64 / x86-64

Translation works today; building needs a Linux sysroot. With a sysroot at
`$LINUX_SYSROOT`:

```sh
build/recomp-studio translate tests/fixtures/apps/bin/arith.exe \
    --target linux-arm64 --output out/arith-linux
# build with an explicit sysroot:
CLANG_ARGS="--target=aarch64-unknown-linux-gnu --sysroot=$LINUX_SYSROOT" \
build/recomp-studio build out/arith-linux
```

Without a sysroot the build reports a missing standard header — that is the
expected, honest result, not a silent failure.

### 5.4 WebAssembly

```sh
build/recomp-studio translate tests/fixtures/apps/bin/arith.exe \
    --target wasm --output out/arith-wasm
build/recomp-studio build out/arith-wasm      # requires wasi-sdk / wasm-ld + a wasm libc
```

The wasm runtime backend (browser I/O instead of file descriptors) is part of
the roadmap.

### 5.5 32-bit guest (PE32) → macOS ARM64

```sh
build/recomp-studio translate tests/fixtures/apps/bin/pe32_abi.exe \
    --target macos-arm64 --output out/pe32abi
build/recomp-studio build  out/pe32abi
build/recomp-studio run    out/pe32abi
build/recomp-studio verify out/pe32abi
```

`pe32_abi` exercises cdecl, stdcall, fastcall and thiscall guest functions, a
relocation-backed function-pointer table (indirect dispatch) and 32-bit address
wrapping. The Unicorn reference runs in `UC_MODE_32` with 32-bit registers, a
32-bit stack and the 32-bit TEB layout.

### 5.6 Every bundled fixture in one loop

```sh
cd tests/fixtures/apps && ./build.sh && cd ../../..
for app in arith tictactoe snake aliasing eflags calls memory flagprobe wide \
           pe32_arith pe32_abi; do
  build/recomp-studio translate tests/fixtures/apps/bin/$app.exe --output out/$app
  build/recomp-studio build out/$app
  build/recomp-studio verify out/$app
done
```

---

## 6. Configuration file

Pass with `--config recomp.toml`. The effective configuration is copied into the
generated project so `build` reproduces it. A full commented example lives at
[`tests/fixtures/apps/recomp.toml`](tests/fixtures/apps/recomp.toml).

```toml
name = "arith"
target = "macos-arm64"
format = "pe"          # or "auto"
architecture = "auto"  # or "x86_64"
strict = true          # false emits a diagnostic stub instead of failing

stack_top = 0x170000000
heap_base = 0x168000000
entry_point_rva = 0x1c30

compiler = "clang++"
compile_flags = ["-O2"]

# Advanced controls
stub_function     = [0x140001000]              # replace a guest function with a no-op
native_override   = ["0x140001530: my_impl"]   # HLE: replace with a host function
instruction_patch = ["0x140001001: b9 f4 ff ff ff"]
extra_sources     = ["src/my_impl.cpp"]
```

### 6.1 Example: stub a function

```toml
# no_newlines.toml
target = "macos-arm64"
stub_function = [0x140001000]
```

```sh
build/recomp-studio translate tests/fixtures/apps/bin/arith.exe \
    --output out/stubbed --config no_newlines.toml
build/recomp-studio build out/stubbed
build/recomp-studio run   out/stubbed     # the stubbed helper now returns immediately
```

### 6.2 Example: native override (HLE)

`src/my_impl.cpp`:

```cpp
#include "recomp_runtime.hpp"
#include <cstdio>
using namespace recomp;

extern "C" void my_impl(GuestContext* context) {
  std::fputc('\n', stdout);
  context->registers[4] += 8;   // pop the guest return address, like a guest function
}
```

```toml
# hle.toml
target = "macos-arm64"
native_override = ["0x140001000: my_impl"]
extra_sources   = ["src/my_impl.cpp"]
```

```sh
build/recomp-studio translate tests/fixtures/apps/bin/arith.exe --output out/hle --config hle.toml
build/recomp-studio build out/hle && build/recomp-studio run out/hle
```

A native override must be a complete replacement: it receives the context and is
responsible for popping the guest return address (`context->registers[4] += 8`)
before returning.

### 6.3 Example: patch an instruction

```toml
# patch.toml — send the program's output to stderr instead of stdout
target = "macos-arm64"
instruction_patch = ["0x140001001: b9 f4 ff ff ff"]   # mov ecx, STDERR_HANDLE
```

```sh
build/recomp-studio translate tests/fixtures/apps/bin/arith.exe --output out/patched --config patch.toml
build/recomp-studio build out/patched && build/recomp-studio run out/patched
```

---

## 7. Verification and the repair harness

### 7.1 What verification proves

`verify` reconstructs the initial machine state, executes the **original x86-64
code** under Unicorn with the same Win32 shims as the runtime, and compares:

1. **Output** — the bytes written to standard output must match exactly.
2. **Trace** — the sequence of executed guest addresses must match; the first
   divergence names the responsible instruction.

Passing means the compiled host binary behaves identically to the original
machine code for the observed execution. It is not a proof of universal
equivalence.

### 7.2 Reading a failure

```sh
build/recomp-studio repair <image> --output out/x
```

```
  [1] functions=670 imports=153 built=yes verified=no
      first control-flow divergence at step 0: ... unsupported mnemonics: addsd, bts, vpxor
report: out/x/reports/harness
```

Each iteration writes `reports/harness/iteration-N.json` with the function counts,
build status, verification status, divergence addresses and diagnosis.

### 7.3 Agent adapter

```sh
build/recomp-studio repair <image> --output out/x --budget 4 --agent "my-coding-agent"
```

The agent command receives the path of the iteration report as its argument. After
the agent returns, the harness rebuilds the studio and retries, up to `--budget`
iterations. Without `--agent` it runs in deterministic offline mode and stops
after the first diagnosis.

---

## 8. Writing your own test fixture

Fixtures are ordinary C programs compiled to real Windows PE files.

```c
// myapp.c
#include "fy.h"          // provides out(), outi(), crlf() and recomp_entry()
int app_main(void) {
  out("hello"); crlf();
  return 0;
}
```

Build for x86-64 or IA-32 (both supported):

```sh
x86_64-w64-mingw32-gcc -O2 -nostdlib -ffreestanding \
    -fno-asynchronous-unwind-tables -fno-stack-protector \
    -fno-tree-vectorize -fno-tree-slp-vectorize \
    -Wl,-e,recomp_entry -Wl,--subsystem,console \
    -o myapp.exe myapp.c -lkernel32 -lgcc

# 32-bit: for a real PE32 image, including the stdcall import ABI
i686-w64-mingw32-gcc -O2 -nostdlib -ffreestanding \
    -fno-asynchronous-unwind-tables -fno-stack-protector \
    -fno-tree-vectorize -fno-tree-slp-vectorize \
    -Wl,--no-insert-timestamp -Wl,-e,recomp_entry -Wl,--subsystem,console \
    -o myapp32.exe myapp.c -lkernel32 -lgcc
```

`tests/fixtures/apps/build.sh` builds all bundled fixtures; override the compiler
with `CC=…`.

---

## 9. Diagnostics and troubleshooting

| Symptom | Meaning | Action |
| --- | --- | --- |
| `not a DOS MZ executable` | Input is not a PE file | Supply a Windows PE executable |
| `unsupported PE optional header magic` | Not PE32/PE32+ | Only PE32/PE32+ are accepted |
| `unsupported instruction '<mnemonic>'` on a PE32 image | The 32-bit lifter has no rule for it | Set `strict = false` to stub the function, or extend the lifter |
| `unsupported instruction '<mnemonic>'` | The lifter has no rule | Set `strict = false` to stub the function, or extend the lifter |
| `indirect call to unmapped guest address` | Target never discovered | The call is genuine; add the entry as an export/manual function |
| `unimplemented Win32 import <dll>!<name>` | Missing shim | Add a shim in `runtime/recomp_runtime.cpp` |
| `recomp: N/M imports implemented; UNSUPPORTED: …` | Startup census | Informational; lists shims that will fail if called |
| `fatal error: 'cstddef' file not found` (Linux/wasm) | No cross sysroot | Provide a sysroot/toolchain for that target |
| `build failed: …` | Compiler error in generated code | Re-run with `strict = false`; report the instruction |

`RECOMP_TRACE=<path>` makes the generated binary write its executed guest
addresses to `<path>` (used by the trace comparison).

---

## 10. Limitations

- Both **PE32+ x86-64** and **PE32 x86** input are lifted. The 32-bit path
  models 4-byte pointers, wrapping addresses, the 32-bit TEB layout and stdcall
  import cleanup; it is verified against the Unicorn x86-32 reference.
- **x87** (80-bit) floating point is modelled in the context but not yet lifted;
  MMX is not implemented.
- Graphics APIs (`user32`, `gdi32`, `ddraw`, `d3d8/9`) have no shims yet — the
  current shim set is a kernel32 subset.
- The Wine-compatible shim set is small and intentionally fail-closed: unknown
  imports report an error instead of returning fabricated success.
- **Linux** and **WebAssembly** targets are wired through the target table but
  need their platform runtimes and sysroots to build and run.
- No claim is made that any specific commercial application is playable; coverage
  is stated per instruction class and per import.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the roadmap that addresses these.
