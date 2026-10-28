# Runtime Provider Backlog

This is the implementation map for the complete symbol-level list in
[SHIM_INVENTORY.md](SHIM_INVENTORY.md). It is deliberately a provider plan,
not a claim that an import is a working native port. Each provider must retain
the upstream license and pass a representative guest test before its symbols
move out of the inventory.

The current corpus contains 302 Windows executables, 73 inputs with unresolved
imports, and 2,194 unique unresolved imports after the console/heap slice.

## Reusable source map

| Priority provider | Imports routed here | Local/open source implementation to adapt | License and integration boundary | Representative corpus consumers |
| --- | ---: | --- | --- | --- |
| Kernel32 console, heap, and basic file mappings | `kernel32.dll` console/heap/mapping APIs | `/Users/haseeb-mir/Downloads/recomp-research/project-igi-browser/host/kernel32.c` (`HeapSize`, console, `CreateFileMappingA`, `MapViewOfFile`) | MIT; adapt through `GuestContext`, retain `third_party/project-igi-browser-LICENSE` | `bat`, `fd`, `ripgrep`, `notepad`, PuTTY utilities |
| Kernel32 filesystem, path, directory enumeration | `Find*FileW`, path, file-info, file-time APIs | Wine `dlls/kernelbase/file.c`; existing Recomp handle-table adapters in `runtime/guest_file_system.hpp` | Wine is LGPL-2.1+; use it as behavioral/source reference unless a separately attributable provider boundary is introduced | `bat`, `fd`, `ripgrep`, `notepad`, SuperTux |
| Kernel32 threads, waits, process state, SEH | `CreateThread`, `Wait*`, SRW, `RaiseException`, `RtlUnwind*`, context APIs | Wine `dlls/kernelbase/thread.c`, `dlls/ntdll/unix/thread.c`; project-igi browser `host/kernel32.c` has limited `CreateThread`/`RaiseException` behavior | Wine LGPL-2.1+ requires a deliberate provider boundary; project-igi browser is MIT but its exception path intentionally traps | MSVC CLI games, Rust tools, PuTTY utilities |
| UCRT / VCRuntime C ABI | `api-ms-win-crt-*`, `vcruntime140*` C functions and startup | Wine `dlls/ucrtbase/*`, `dlls/msvcrt/*`; existing host-CRT adapters in `runtime/recomp_runtime.cpp`; mingw-w64 CRT is a compatibility reference | Wine LGPL-2.1+ and mingw-w64’s per-file notices must be preserved; do not pretend C++ object ABI is plain C | C/C++ CLI games, `bat`, `snake`, SuperTux |
| MSVC C++ ABI and exception model | decorated `msvcp140.dll`, `vcruntime140.dll` C++ exports | Wine `dlls/msvcp140/*`, `dlls/vcruntime140/*` | LGPL-2.1+; needs an isolated ABI provider, not individual no-op symbols | `snake-game.exe`, SuperTux, OpenLieroX |
| User32/GDI GUI window, menus, clipboard, input | `user32.dll`, `gdi32.dll`, `uxtheme.dll`, `comctl32.dll` imports | Wine `dlls/user32/*`, `dlls/gdi32/*`; existing headless adapters in `runtime/recomp_runtime.cpp` | Wine LGPL-2.1+ reference; a real macOS GUI provider must preserve message/handle semantics | `legacy-notepad-x64.exe`, Cube, PuTTY, ClipJar |
| DirectX 7, input, audio, AVI, WinMM | `ddraw`, `dinput`, `dsound`, `avifil32`, `winmm`, `ole32` imports | `igi-recomp/shim/src/{ddraw,dinput,dsound,avifil32,winmm,ole32}.c`; fallback `project-igi-browser/host/{ddraw7,dinput,dsound,mm}.c` | MIT. Their COM/CPU contexts differ, so adapt provider slices with an explicit renderer/input/audio backend | Project I.G.I. executables |
| Network and TLS | `ws2_32.dll`, `wsock32.dll`, `secur32.dll`, `schannel.dll`, crypto imports | Wine `dlls/ws2_32/*`, `dlls/secur32/*`; host POSIX socket/TLS libraries behind guest handle adapters | Wine LGPL-2.1+ reference; network and credential behavior must never be faked as success | `bat`, `ripgrep`, PuTTY suite, OpenLieroX |
| Registry, SID, token, crypto | `advapi32.dll`, `crypt32.dll`, `bcrypt*.dll` imports | Wine `dlls/advapi32/*`, `dlls/crypt32/*`, `dlls/bcrypt/*` | Wine LGPL-2.1+ reference; use a host-backed virtual registry and explicit unsupported security semantics | `bat`, `busybox`, PuTTY utilities, Powder Toy |
| Application-supplied libraries | `libcurl`, OpenAL, gd, libstdc++, Java/.NET or packed-input dependencies | The app’s matching upstream library, or a dedicated language frontend | Not a Win32 shim. Record its independent license and do not add it to kernel32 | OpenLieroX, managed/paked inputs |

## Execution order

1. Finish the MIT kernel32 slice: `FindFirst/NextFileW`, mappings, console input,
   then validate `bat`, `fd`, and `notepad` on the native candidate.
2. Add UCRT C functions in groups that can be verified against host libc; keep
   exceptions and the MSVC C++ object ABI separate.
3. Add GUI behavior as a real message/handle provider, beginning with the
   notepad menu, clipboard, and text paths; static import coverage alone is not
   GUI proof.
4. Build DirectX/input/audio providers from the MIT IGI sources and exercise
   a single IGI executable only after native compilation can complete.
5. Route managed, packed, and third-party-library imports to frontends or
   dedicated providers. They cannot be fixed by adding a `kernel32` entry.

## Attribution rule

Never bulk-copy Wine, QEMU, Unicorn, or a system CRT into the core runtime.
For every upstream-derived provider slice, add its license text and a source
notice in `THIRD_PARTY_NOTICES.md`, state the original file and revision, and
test its guest ABI separately. This keeps the native port honest and the
license obligations reviewable.
