# Reusable runtime patterns from local recompiler projects

This report compares the local research projects before adapting their code.
The goal is to generalize infrastructure for `autorecomp`, while keeping game
profiles and assets outside the shared runtime.

## Cricket 07 browser

`cricket07-browser` separates translated CPU code from a host layer. Its
`host/` directory provides window/input, files, threads, timers, DirectSound,
DirectInput, and Direct3D-to-WebGPU adapters. `runtime/` owns the guest memory,
CPU state, interpreter fallback, and differential-test hooks. The same
translated code can be compiled for native macOS or WebAssembly because the
host contract is separate from the generated functions.

Reusable pattern: define platform interfaces for files, clocks, threads,
input, windows, audio, and graphics; provide a native backend first and keep
browser backends optional. Preserve the original guest address layout and put
all host state behind handles rather than returning process-specific pointers.

## igi-recomp

`igi-recomp/shim/` uses a small import-shim contract and separates common
platform code from SDL, Vita, rendering, DirectDraw, DirectInput, DirectSound,
and Win32 adapters. `platform_common.c` and `platform.h` are the useful general
boundary. `user32.c` demonstrates the required message path: register a class,
create a host window, queue a message, and re-enter the guest window procedure.
The individual `SHIM()` bodies are title-specific evidence and must be ported
only when their ABI and guest memory assumptions match.

Reusable pattern: make the import table data-driven, use one guest handle table,
and route all window callbacks through a checked guest-function lookup. Keep
SDL/platform code behind a backend interface instead of embedding it in each
game shim.

## project-igi-browser

`project-igi-browser` applies the same split to a browser target. Its `host/`
files isolate DirectDraw, D3D8, DirectSound, windowing, scheduling, and file
access. This confirms that graphics and audio are host services, not instruction
semantics. Its scheduler and render-command recording are useful general ideas
for platforms whose drawing API must run on a main thread.

Reusable pattern: record render commands from guest threads, replay them on the
host graphics thread, and use a deterministic virtual clock for verification.

## N64Recomp

`N64Recomp` is a different ISA and input format, but its configuration-driven
generator has reusable orchestration ideas: explicit input/output metadata,
stubbed and ignored functions, instruction patches, symbol lists, and a runtime
contract for indirect function lookup and relocations. It is not a Win32 runtime
and its MIPS generator cannot be copied into the PE pipeline.

Reusable pattern: expose the same concepts in `autorecomp` as a generated
manifest and profile: host backend, import overrides, function stubs, patches,
and checked indirect-call policy.

## Recomp Studio integration order

The shared runtime should be split into these general services:

1. guest handle table and path sandbox;
2. CRT stream/file operations (`fopen`, `fclose`, `fread`, `fwrite`);
3. window class registry, host window, message queue, and guest callback;
4. GDI drawing/text and common controls;
5. DirectDraw/DirectSound/input adapters;
6. native macOS app-bundle packaging and resource copying.

Each service gets a small PE32 and PE32+ fixture, differential verification,
and a real corpus run. The current `cube.exe` sequence has already verified the
shared import path through `InitCommonControls`, `LoadIconA`, `LoadCursorA`, and
`RegisterClassA`; `fopen` is the next boundary.

## Provenance and licensing

The local projects are used as source references or narrowly adapted code. Their
licenses and exact revisions must be recorded in `THIRD_PARTY_NOTICES.md` before
any source is copied. Game profiles, asset paths, and title-specific rendering
logic stay outside the general runtime.
