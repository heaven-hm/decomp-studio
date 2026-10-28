# Recomp Studio: `autorecomp` Pipeline & Harness Architecture

A technical specification of the automated static recompilation pipeline in `recomp-studio`, explaining each processing step and its role as an execution/verification harness.

---

## The 9-Step `autorecomp` Pipeline

### 1. `[1/9] detect host and target`
Probes the host OS, architecture, and toolchain (Clang/LLVM), determining the target platform (e.g., `Darwin/arm64` on Apple Silicon) and setting cross-compilation rules for translation.

### 2. `[2/9] inspect executable`
Parses the binary’s PE headers, sections, entry point, image base, and Import Table (`.idata`), validating format compatibility (`PE32` x86 / `PE32+` x64) and extracting metadata.

### 3. `[3/9] recover functions`
Performs recursive disassembly and basic-block analysis from the entry point and exports, identifying function boundaries, control flow graphs (CFGs), and indirect call targets across the binary.

### 4. `[4/9] classify instruction coverage`
Maps every disassembled x86 assembly instruction against the lifter’s semantics database, verifying 100% semantic lifting coverage and flagging any unsupported floating-point or vector operations.

### 5. `[5/9] check import compatibility`
Scans external Win32 API calls (`kernel32`, `user32`, `gdi32`) against built-in POSIX/macOS runtime shims, verifying every imported system function has a corresponding host implementation.

### 6. `[6/9] translate to host source`
Emits portable, high-fidelity C++20 code (`guest.cpp`), mapping x86 register state, memory pages, stack frames, and control-flow jumps directly to native host instructions and ABI helpers.

### 7. `[7/9] build native executable`
Compiles generated C++ code alongside `recomp_runtime.cpp` using the host compiler (`clang++ -O2`), producing a native Mach-O executable (`recomp-guest`) with zero external emulation layers.

### 8. `[8/9] run native executable`
Executes the compiled native binary inside an isolated process wrapper, capturing standard output, error streams, memory checkpoints, and exit status while enforcing strict timeouts and stdin redirection.

### 9. `[9/9] verify against the reference`
Runs the original Windows binary through an emulated reference CPU (Unicorn engine), differentially comparing instruction traces, CPU registers, memory checkpoints, and stdout byte-for-byte against the native candidate.

---

## Why `recomp-studio` is an Execution Harness

In software engineering, a **harness** (test harness) is a specialized framework that surrounds, controls, and instruments a target program to observe its behavior under identical conditions.

`recomp-studio` functions as a harness through four core capabilities:

1. **Controlled Environment Injection:**
   It wraps the recompiled program, injecting deterministic inputs (virtual stdin via `RECOMP_STDIN_FILE` / `recomp-stdin.txt`, mock environment variables, and memory layouts).

2. **Dual Side-by-Side Execution:**
   It runs the recompiled native app alongside an emulated reference engine under identical initial machine states.

3. **Differential Instrumentation:**
   It samples and compares machine states (registers, memory windows, and output streams) byte-for-byte to verify mathematical equivalence.

4. **Safety Boundaries:**
   It enforces execution timeouts (`--timeout`), traps signals, catches unshimmed API calls, and terminates rogue loops safely without crashing the host system.
