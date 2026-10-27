# Ordered Win32 shim port plan — getting the first application running

**Task:** task-9 · **Author:** teammate `upstream-eval` · **Date:** 2026-10-27
**Write scope:** this file only. No code, test or other report was modified.

**Sources.** `reports/gap-census.md` (the 16-binary ranked census, task-5), `reports/igi-recomp-reuse.md`
(task-6), the per-binary `imports --json` payloads the census left in `/tmp/gapcensus/*.json`
(verified still present and re-analysed here), the igi-recomp checkout at
`research/upstream/igi-recomp` (commit `278eaf6394f7f42c7de6cffef2cf982154f59899`), and the current
working tree of `runtime/` and `core/`.

**Method.** Every count below was produced by script from those JSON payloads and from parsing the
`SHIM(dll, name)` lines in `research/upstream/igi-recomp/shim/src/*.c`. No number is estimated.

> **Line-number caveat.** `runtime/recomp_runtime.cpp` and `runtime/recomp_runtime.hpp` are being
> edited concurrently (they grew from 656/44435 B to 797/1409 lines during this task). Every line
> reference to those two files below was re-verified against the tree as read at the end of this task;
> the *semantics* cited (central stack cleanup, synthetic heap handle, 4-symbol reference model) were
> each re-read at that point.

---

## 0. Answer in brief

1. **Largest-unlock batch: Batch 1 — the kernel32 CRT/process cluster, 14 shims.** 12 of the 16
   binaries import at least one of them; it removes up to 14 imports from a single binary (igi.exe)
   and 1–12 from nine others. All 14 bodies exist in igi-recomp. It splits into **1a (9 shims, purely
   mechanical, 10 binaries)** and **1b (5 shims, requires a Win32 handle table, 12 binaries)**.
2. **Would any batch get a genuine application to `verify`? No.** Not Batch 1, not Batches 1–2, and
   not all 96 applicable shims together. `verify` fails closed on any import the **reference** does not
   model, and the reference models exactly **4** imports (`core/verification/differential_harness.cpp:144`,
   `:147`, `:156`, `:162`) while the runtime has **63** shims — and after porting everything igi-recomp
   offers, 15 of the 16 applications still have 1–708 imports that igi-recomp does not implement at all.
   §6 gives the evidence and the two ways to get a genuine `verify` anyway.
3. **Cheapest path to a genuine application *running* (not verified): igi.exe, driven on demand.** Its
   imports are 100% covered by igi-recomp, the loader binds every import to a thunk and only fails when
   an unbound thunk is *called* (`runtime/recomp_runtime.cpp:705`, bound at `:743`), so the practical
   loop is: run → hit the first unbound import → port that one shim → repeat. That beats porting all 97
   up front. See §7.

---

## 1. The ranked table — igi-recomp bodies only

96 of igi-recomp's 128 shims are missing from at least one of the 16 binaries. Ranked by the number of
binaries that import the symbol and currently have no shim (the census's "binaries" column, recomputed
here per symbol).

| # | shim (library!symbol) | binaries | igi-recomp body |
| --- | --- | --- | --- |
| 1 | `kernel32.dll!CloseHandle` | 11 | `shim/src/kernel32.c:278` |
| 2 | `kernel32.dll!FindClose` | 11 | `shim/src/kernel32.c:910` |
| 3 | `kernel32.dll!FlushFileBuffers` | 8 | `shim/src/kernel32.c:764` |
| 4 | `kernel32.dll!FreeEnvironmentStringsW` | 8 | `shim/src/kernel32.c:291` |
| 5 | `kernel32.dll!GetEnvironmentStringsW` | 8 | `shim/src/kernel32.c:289` |
| 6 | `kernel32.dll!HeapReAlloc` | 8 | `shim/src/kernel32.c:342` |
| 7 | `kernel32.dll!RaiseException` | 8 | `shim/src/kernel32.c:250` |
| 8 | `kernel32.dll!CreateMutexA` | 7 | `shim/src/kernel32.c:270` |
| 9 | `kernel32.dll!GetCPInfo` | 7 | `shim/src/kernel32.c:1034` |
| 10 | `kernel32.dll!GetFileType` | 7 | `shim/src/kernel32.c:308` |
| 11 | `kernel32.dll!ReleaseMutex` | 7 | `shim/src/kernel32.c:276` |
| 12 | `kernel32.dll!GetStringTypeW` | 6 | `shim/src/kernel32.c:1107` |
| 13 | `kernel32.dll!LCMapStringW` | 6 | `shim/src/kernel32.c:1146` |
| 14 | `kernel32.dll!SetStdHandle` | 6 | `shim/src/kernel32.c:306` |
| 15 | `gdi32.dll!DeleteDC` | 5 | `shim/src/user32.c:339` |
| 16 | `user32.dll!GetDC` | 5 | `shim/src/user32.c:250` |
| 17 | `user32.dll!GetForegroundWindow` | 5 | `shim/src/user32.c:194` |
| 18 | `gdi32.dll!GetDeviceCaps` | 4 | `shim/src/user32.c:323` |
| 19 | `kernel32.dll!CreateFileA` | 4 | `shim/src/kernel32.c:413` |
| 20 | `kernel32.dll!GetEnvironmentVariableA` | 4 | `shim/src/kernel32.c:292` |
| 21 | `kernel32.dll!OutputDebugStringA` | 4 | `shim/src/kernel32.c:262` |
| 22 | `user32.dll!ClientToScreen` | 4 | `shim/src/user32.c:236` |
| 23 | `user32.dll!DestroyWindow` | 4 | `shim/src/user32.c:169` |
| 24 | `user32.dll!GetClientRect` | 4 | `shim/src/user32.c:226` |
| 25 | `user32.dll!ReleaseDC` | 4 | `shim/src/user32.c:251` |
| 26 | `user32.dll!SetForegroundWindow` | 4 | `shim/src/user32.c:193` |
| 27 | `user32.dll!SetWindowPos` | 4 | `shim/src/user32.c:202` |
| 28 | `user32.dll!ShowWindow` | 4 | `shim/src/user32.c:176` |
| 29 | `user32.dll!TranslateMessage` | 4 | `shim/src/user32.c:312` |
| 30 | `kernel32.dll!DeleteFileA` | 3 | `shim/src/kernel32.c:766` |
| 31 | `kernel32.dll!FindFirstFileA` | 3 | `shim/src/kernel32.c:874` |
| 32 | `kernel32.dll!FindNextFileA` | 3 | `shim/src/kernel32.c:901` |
| 33 | `kernel32.dll!GetLocalTime` | 3 | `shim/src/kernel32.c:1012` |
| 34 | `kernel32.dll!RtlUnwind` | 3 | `shim/src/kernel32.c:255` |
| 35 | `kernel32.dll!SetEndOfFile` | 3 | `shim/src/kernel32.c:752` |
| 36 | `kernel32.dll!SetFilePointer` | 3 | `shim/src/kernel32.c:709` |
| 37 | `ole32.dll!CoCreateInstance` | 3 | `shim/src/ole32.c:34` |
| 38 | `ole32.dll!CoUninitialize` | 3 | `shim/src/ole32.c:6` |
| 39 | `user32.dll!GetSystemMetrics` | 3 | `shim/src/user32.c:239` |
| 40 | `user32.dll!InvalidateRect` | 3 | `shim/src/user32.c:191` |
| 41 | `user32.dll!PostQuitMessage` | 3 | `shim/src/user32.c:290` |
| 42 | `user32.dll!SetFocus` | 3 | `shim/src/user32.c:192` |
| 43 | `kernel32.dll!GetDriveTypeA` | 2 | `shim/src/kernel32.c:799` |
| 44 | `kernel32.dll!GetVersionExA` | 2 | `shim/src/kernel32.c:121` |
| 45 | `user32.dll!MessageBoxA` | 2 | `shim/src/user32.c:264` |
| 46 | `user32.dll!PeekMessageA` | 2 | `shim/src/user32.c:297` |
| 47 | `user32.dll!ShowCursor` | 2 | `shim/src/user32.c:257` |
| 48 | `user32.dll!UpdateWindow` | 2 | `shim/src/user32.c:190` |
| 49–58 | `avifil32.dll!` `AVIFileExit` `AVIFileGetStream` `AVIFileInfoA` `AVIFileInit` `AVIFileOpenA` `AVIFileRelease` `AVIStreamInfoA` `AVIStreamRead` `AVIStreamReadFormat` `AVIStreamRelease` | 1 each | `shim/src/avifil32.c:138, 206, 190, 137, 140, 284, 220, 256, 242, 282` |
| 59–60 | `ddraw.dll!DirectDrawCreateEx` `DirectDrawEnumerateExA` | 1 each | `shim/src/ddraw.c:1172, 1180` |
| 61–62 | `dinput.dll!DirectInputCreateA` `DirectInputCreateEx` | 1 each | `shim/src/dinput.c:342, 349` |
| 63 | `gdi32.dll!CreateICA` | 1 | `shim/src/user32.c:338` |
| 64–70 | `kernel32.dll!` `CompareFileTime` `DebugBreak` `GetFileTime` `GetLocaleInfoA` `GetStringTypeA` `LCMapStringA` `SetHandleCount` | 1 each | `shim/src/kernel32.c:793, 260, 779, 1165, 1096, 1131, 293` |
| 71–74 | `msvfw32.dll!` `ICClose` `ICDecompress` `ICLocate` `ICSendMessage` | 1 each | `shim/src/avifil32.c:386, 398, 339, 369` |
| 75 | `ole32.dll!CoInitialize` | 1 | `shim/src/ole32.c:5` |
| 76–87 | `user32.dll!` `AdjustWindowRect` `CreateWindowExA` `DefWindowProcA` `DispatchMessageA` `GetMessageA` `GetWindowLongA` `LoadCursorA` `LoadIconA` `PostMessageA` `RegisterClassA` `SetWindowTextA` `UnregisterClassA` | 1 each | `shim/src/user32.c:237, 118, 270, 314, 304, 212, 253, 252, 284, 100, 196, 116` |
| 88–96 | `winmm.dll!` `mciSendCommandA` `mixerClose` `mixerGetControlDetailsA` `mixerGetDevCapsA` `mixerGetLineControlsA` `mixerGetLineInfoA` `mixerGetNumDevs` `mixerOpen` `mixerSetControlDetails` | 1 each | `shim/src/winmm.c:8, 16, 20, 17, 19, 18, 14, 15, 21` |

**Notes on the table.**

- **The 97th applicable shim is not in this table** because it is an ordinal import:
  `dsound.dll!#1` → `imp_dsound__1` at `shim/src/dsound.c:882`. Our parser names ordinal imports
  literally `"#<n>"` (`core/binary/pe.cpp:230`), and the shim lookup is an exact string compare
  (`runtime/win32_abi.hpp:89-90`), so an ordinal shim must be registered under the literal key `#1`.
  That is a real trap for any of the three ordinal imports in the corpus
  (`dsound.dll!#1`, `shell32.dll!#25`, `shlwapi.dll!#12`).
- **The remaining 31 of igi-recomp's 128 shims are already implemented here** (the 31 kernel32 imports
  the runtime already shims), so they are not "missing" anywhere and do not appear.
- **The census's top-ranked symbols are only partly igi-recomp-coverable.** `FindClose` (11) and
  `CloseHandle` (11) are; the `Rtl*` SEH trio (10–11 binaries) and the `W`-variants
  (`CreateFileW` 9, `GetCommandLineW` 9, `GetModuleFileNameW` 9, `FindFirstFileExW` 8,
  `FindNextFileW` 8, `SetFilePointerEx` 8, `LocalFree` 8, `InitializeSListHead` 9) are **not** — those
  must be written, using the A-variant bodies as the template (§4).
- The `Rtl*` trio is imported from **kernel32.dll by 9–10 binaries** and from `ntdll.dll` by 1
  (measured per library). Since our lookup is library-aware, both spellings need a row.

---

## 2. Batches, ordered by how many binaries they unblock

"Binaries touched" = binaries that import at least one shim in the batch. "Binaries closed" = binaries
whose missing-import count reaches 0. Every batch is independently landable and testable: each shim is
observable through `imports` (count goes down) and through a targeted run of one binary.

| order | batch | shims | binaries touched | binaries closed | prerequisite |
| --- | --- | --- | --- | --- | --- |
| **0** | **Reference parity** (not a shim port) | — | all | — | must accompany every batch, or `verify` cannot pass |
| **1a** | kernel32 CRT cluster, mechanical half | 9 | 10 | 0 | none — landable today |
| **1b** | kernel32 CRT cluster, handle/heap half | 5 | 12 | 0 | Win32 handle table (heap already exists) |
| 2 | kernel32 file/find cluster (A-variants) | 11 | 6 | 0 | handle table + host path mapper |
| 3 | SEH: `RtlCaptureContext`/`RtlLookupFunctionEntry`/`RtlVirtualUnwind`/`RtlUnwindEx` | 4 | 11 | 0 | **new PE exception-directory (.pdata) parsing** |
| 4 | `W`-variant twins of the file/CRT cluster | ~10 | 9 | 0 | templates from Batch 2 |
| 5 | memory/sync/module/console/locale remainder | ~20 | 9 | 0 | heap exists; parts need console + registry |
| 6 | igi.exe platform surface (user32/DirectX/AVI/audio) | 64 | 1 | **1 (igi.exe)** | SDL2/OpenGL platform layer, COM model, AVI parser |
| 7 | imgview64 closer (GDI+/comctl32/ordinals) | 6 | 1 | **1 (imgview64)** | GDI+ fakes, ordinal identification |

**Batch 1 in detail — the largest unlock.**

*1a, mechanical (9 shims, 10 binaries touched):* `FlushFileBuffers`, `FreeEnvironmentStringsW`,
`GetEnvironmentStringsW`, `RaiseException`*, `GetCPInfo`, `ReleaseMutex`, `GetStringTypeW`,
`LCMapStringW`, `SetStdHandle`. (*`RaiseException` is mechanical to port but needs a *policy* decision —
see §3.7.) Impact per binary: fd −9, igi −9, plink −9, rg −9, legacy-notepad −8, Pixeltetris −8,
clipjar −5, bat −4, powder −2, openlierox −1.

*1b, infrastructure-backed (5 shims, 12 binaries touched):* `CloseHandle`, `FindClose`, `CreateMutexA`,
`GetFileType`, `HeapReAlloc`. All five need a **Win32 handle table**; `HeapReAlloc` needs a heap, which
now exists (`runtime/recomp_runtime.cpp:240` `win32_heap_alloc` walks a real free list), so only
`HeapReAlloc` itself is missing from the heap family. Impact per binary: bat −5, fd −5, igi −5,
plink −5, rg −5, clipjar −4, legacy-notepad −4, Pixeltetris −4, powder −3, supertux −2, openlierox −1,
tetris −1.

*Batch 1 combined:* 12 binaries touched, and **igi.exe is the single biggest beneficiary (−14)**, which
is why this is the right first batch even though no binary is closed by it.

---

## 3. Batch 1: exact per-shim adaptation notes

**The contract, restated because it is the one thing that must not be got wrong.** igi-recomp shims are
`void imp_<dll>_<name>(Ctx *c)` (`shim/include/shim.h:8`) and they end with
`stdcall_ret(c, value, nargs)` (`runtime/include/runtime.h:69-73`), which sets `eax` **and pops
`nargs + 1` dwords**. Our shims are `void (*)(GuestContext*)` (`runtime/recomp_runtime.cpp:380-386`)
and must **not** touch the stack: `invoke_import_thunk` pops centrally
(`runtime/recomp_runtime.cpp:101-112`) using `win32_import_stack_cleanup`
(`runtime/win32_abi.hpp:98-104`), which reads the `argument_count`/`callee_cleans_stack` row for the
symbol. Consequences for every port:

- `stdcall_ret(c, v, n)` → `set_import_result(context, v)` (`runtime/recomp_runtime.hpp:1368`) — **the
  `n` argument disappears from the shim** and must instead be recorded as `argument_count` in
  `kWin32ImportAbiTable` (`runtime/win32_abi.hpp:20-84`), or the guest stack will not be cleaned on
  32-bit guests. (For 64-bit guests the cleanup is not applied at all — `recomp_runtime.cpp:105` — so a
  wrong `argument_count` is silent on PE32+ and fatal on PE32. igi.exe is PE32, so this matters.)
- `ARG(n)` (`runtime/include/runtime.h:67`, = `[esp+4+4n]`) → `import_argument(context, n)`
  (`runtime/recomp_runtime.hpp:1354`), which is arch-aware.
- `RD8/RD16/RD32` → `load_guest_memory(context, addr, size)`; `WR8/WR16/WR32` →
  `store_guest_memory(context, addr, value, size)`.
- `gptr(a)`/`gstr(a)` → `guest_memory + a` (`recomp_runtime.hpp:53`); `gstr` + `strlen` →
  `read_guest_string(...)`.
- Each shim needs **two** table rows — `kShims` (`recomp_runtime.cpp:386`) *and*
  `kWin32ImportAbiTable` (`win32_abi.hpp:20`) — because `is_shimmed_import`
  (`apps/cli/main.cpp:190-195`) reads the ABI table, so a shim registered only in `kShims` still
  reports as missing.
- Each shim needs a **reference-side branch** in `emulate_shim`
  (`core/verification/differential_harness.cpp:144-176`) or `verify` stops with
  "reference does not model …" (§6).

### 3.1 `CloseHandle` — `shim/src/kernel32.c:278` (5 lines) · 1 arg · **Batch 1b**

```c
SHIM(kernel32, CloseHandle) { handle_close(ARG(0)); stdcall_ret(c, 1, 1); }
```

| igi-recomp | Recomp Studio |
| --- | --- |
| `void imp_kernel32_CloseHandle(Ctx *c)` | `void win32_close_handle(GuestContext* context)` |
| `ARG(0)` | `import_argument(context, 0)` |
| `handle_close(...)` | **does not exist** — requires a new handle table |
| `stdcall_ret(c, 1, 1)` | `set_import_result(context, 1)` + ABI row `{"kernel32.dll","CloseHandle",1,true}` |

### 3.2 `FindClose` — `shim/src/kernel32.c:910` (10 lines) · 1 arg · **Batch 1b**

```c
HandleObj *o = handle_get(ARG(0), H_FIND);
if (o) { FindState *f = o->ptr; closedir(f->dir); }
handle_close(ARG(0));
stdcall_ret(c, 1, 1);
```

Same mapping as 3.1, plus: `FindState`/`closedir` mean the handle table must hold a **host pointer**
(the `DIR*`) for a guest handle, i.e. the table is not a pure guest-memory structure. Our runtime has no
such table today (`grep handle_table` → nothing).

### 3.3 `FlushFileBuffers` — `shim/src/kernel32.c:764` (1 line) · 1 arg · **Batch 1a**

`stdcall_ret(c, 1, 1)` → `set_import_result(context, 1)`, ABI row `{1, true}`. Note the body returns
success **without flushing**; that is deliberate in igi-recomp and must be reproduced identically on the
reference side, or the traces diverge on file-heavy binaries.

### 3.4 `FreeEnvironmentStringsW` — `shim/src/kernel32.c:291` (1 line) · 1 arg · **Batch 1a**

`stdcall_ret(c, 1, 1)` → `set_import_result(context, 1)`. Pure.

### 3.5 `GetEnvironmentStringsW` — `shim/src/kernel32.c:289` (1 line) · 0 args · **Batch 1a**

```c
SHIM(kernel32, GetEnvironmentStringsW) { stdcall_ret(c, env_block_w, 0); }
```

`env_block_w` is a **guest address** allocated at startup (`shim/src/kernel32.c:286` declares it,
`:1175` allocates it with `scratch_alloc`). Ours becomes
`set_import_result(context, environment_block_w)` — but we must first *create* a wide environment block
in guest memory at startup; our runtime currently has `GetEnvironmentStrings` (ANSI) only. This is the
one shim in 1a that is not a pure rename.

### 3.6 `HeapReAlloc` — `shim/src/kernel32.c:342` (13 lines) · 4 args · **Batch 1b**

```c
uint32_t flags = ARG(1), ptr = ARG(2), size = ARG(3);
uint32_t old = heap_size(ptr);
if (flags & 0x10u) p = size <= old ? ptr : 0u;      /* HEAP_REALLOC_IN_PLACE_ONLY */
else               p = heap_realloc(ptr, size);
if (p && (flags & 0x8u) && size > old) memset(gptr(p + old), 0, size - old);   /* HEAP_ZERO_MEMORY */
stdcall_ret(c, p, 4);
```

Mapping: three `ARG(n)` → `import_argument(context, n)`; `heap_size`/`heap_realloc` → the existing heap
helpers behind `win32_heap_alloc` (`recomp_runtime.cpp:240`); `memset(gptr(p+old), …)` →
`store_guest_memory` in a loop (or a small helper); `stdcall_ret(c, p, 4)` →
`set_import_result(context, p)` + ABI row `{4, true}`. Note `HeapReAlloc` is **absent from our 63
shims** today (verified), so this is a new function on top of existing infrastructure.

### 3.7 `RaiseException` — `shim/src/kernel32.c:250` (4 lines) · 4 args · **Batch 1a (policy needed)**

```c
SHIM(kernel32, RaiseException) { rt_fatal(c, "RaiseException(%08X, flags %08X)", ARG(0), ARG(1)); }
```

igi-recomp **aborts**. Porting that literally means a C++ exception or an MSVC `__CxxThrowException`
kills the process — correct for a program that should not throw, wrong for one that catches. Two
`ARG(n)` → `import_argument`; `rt_fatal` → our `terminate_with_message`. The policy (abort vs.
return-and-continue) must be decided once and mirrored in the reference, because the reference has to
take the same branch.

### 3.8 `CreateMutexA` — `shim/src/kernel32.c:270` (5 lines) · 3 args · **Batch 1b**

```c
win32_set_last_error(0);
stdcall_ret(c, handle_new(H_MUTEX), 3);
```

`ARG(0)`/`ARG(1)` are ignored; needs (a) a handle table, (b) last-error state — our runtime has no
last-error variable (`GetLastError` is a constant-0 shim), so `win32_set_last_error(0)` has no
counterpart and would need one to stay faithful. `stdcall_ret(c, h, 3)` →
`set_import_result(context, h)` + ABI `{3, true}`.

### 3.9 `GetCPInfo` — `shim/src/kernel32.c:1034` (8 lines) · 2 args · **Batch 1a**

```c
uint32_t p = ARG(1);
memset(gptr(p), 0, 20);
WR32(p, 1);
WR8(p + 4u, '?');
stdcall_ret(c, 1, 2);
```

`ARG(1)` → `import_argument(context, 1)`; `memset(gptr(p),0,20)` → 20 `store_guest_memory` byte writes
(or a `store_guest_bytes` helper); `WR32(p,1)` → `store_guest_memory(context, p, 1, 4)`;
`WR8(p+4,'?')` → `store_guest_memory(context, p + 4, '?', 1)`; `stdcall_ret(c,1,2)` →
`set_import_result(context,1)` + ABI `{2, true}`. Purely mechanical.

### 3.10 `GetFileType` — `shim/src/kernel32.c:308` (10 lines) · 1 arg · **Batch 1b**

Reads the handle table (`handle_get(ARG(0), H_FREE)`) and returns 2 (`FILE_TYPE_CHAR`) for `H_STD`, 1
(`FILE_TYPE_DISK`) for `H_FILE`, else 0. Needs the handle table and our std-handle mapping
(`win32_get_std_handle`, `recomp_runtime.cpp:175`) to be expressed as handle-table entries, so that
`GetFileType` can see the type. `ARG(0)` → `import_argument`; `stdcall_ret(c, t, 1)` →
`set_import_result(context, t)` + ABI `{1, true}`.

### 3.11 `ReleaseMutex` — `shim/src/kernel32.c:276` (1 line) · 1 arg · **Batch 1a**

`set_import_result(context, 1)` + ABI `{1, true}`. Pure.

### 3.12 `GetStringTypeW` — `shim/src/kernel32.c:1107` (14 lines) · 4 args · **Batch 1a**

```c
uint32_t src = ARG(1), out = ARG(3);
int32_t n = (int32_t)ARG(2);
if (n < 0) { n = 0; while (RD16(src + n*2u)) n++; n++; }
for (int32_t i = 0; i < n; i++) WR16(out + i*2u, ctype1(RD16(src + i*2u)));
stdcall_ret(c, 1, 4);
```

Mapping: three `ARG(n)` → `import_argument`; `RD16(src + i*2)` →
`load_guest_memory(context, src + i*2, 2)`; `WR16(out + i*2, v)` →
`store_guest_memory(context, out + i*2, v, 2)`; `ctype1` (`shim/src/kernel32.c:1079-1094`, a
`C1_*` classifier built on `isupper/islower/isdigit/isspace/ispunct/iscntrl/isxdigit/isalpha`) must be
copied verbatim as a static helper; `stdcall_ret(c, 1, 4)` → `set_import_result(context,1)` + ABI
`{4, true}`. Mechanical.

### 3.13 `LCMapStringW` — `shim/src/kernel32.c:1146` (18 lines) · 6 args · **Batch 1a**

Same shape as 3.12 with `map_char` (`shim/src/kernel32.c:1122`) instead of `ctype1`, a destination
capacity check (`if (n > dst_n) n = dst_n`), and `stdcall_ret(c, n, 6)` →
`set_import_result(context, n)` + ABI `{6, true}`. `ARG(1),(2),(3),(4),(5)` → `import_argument`; all
`RD16`/`WR16` → `load_guest_memory`/`store_guest_memory`. Mechanical.

### 3.14 `SetStdHandle` — `shim/src/kernel32.c:306` (1 line) · 2 args · **Batch 1a**

`set_import_result(context, 1)` + ABI `{2, true}`. **Behaviour note:** igi-recomp ignores the new
handle; our runtime actually tracks standard handles (`win32_get_std_handle`). Porting the body
literally means *not* storing the value — keep whichever behaviour is chosen identical on the reference
side, because `GetStdHandle`/`SetStdHandle` ordering changes stdout capture.

**ABI rows required by Batch 1** (`runtime/win32_abi.hpp:20-84`), in the table's format:

```cpp
{"kernel32.dll", "CloseHandle", 1, true},              {"kernel32.dll", "FindClose", 1, true},
{"kernel32.dll", "FlushFileBuffers", 1, true},         {"kernel32.dll", "FreeEnvironmentStringsW", 1, true},
{"kernel32.dll", "GetEnvironmentStringsW", 0, true},   {"kernel32.dll", "HeapReAlloc", 4, true},
{"kernel32.dll", "RaiseException", 4, true},           {"kernel32.dll", "CreateMutexA", 3, true},
{"kernel32.dll", "GetCPInfo", 2, true},                {"kernel32.dll", "GetFileType", 1, true},
{"kernel32.dll", "ReleaseMutex", 1, true},             {"kernel32.dll", "GetStringTypeW", 4, true},
{"kernel32.dll", "LCMapStringW", 6, true},             {"kernel32.dll", "SetStdHandle", 2, true},
```

---

## 4. Shims that cannot be ported mechanically

| shim(s) | what is missing | evidence |
| --- | --- | --- |
| `CloseHandle`, `FindClose`, `GetFileType`, `CreateMutexA`, and all of Batch 2 (`CreateFileA`, `FindFirstFileA`, `FindNextFileA`, `SetFilePointer`, `SetEndOfFile`, `DeleteFileA`, `GetFileTime`) | **No Win32 handle table.** igi-recomp's `handle_new`/`handle_get`/`handle_close` + `HandleObj` (`shim/include/shim.h:18-28`, `shim/src/kernel32.c:34-60`) hold a host `int fd` and a host `void*` (a `DIR*`), so guest handles must map to host objects. Our runtime has none (`grep handle_table runtime/recomp_runtime.cpp` → nothing); it uses fixed constants (`GetProcessHeap` and `HeapCreate` both return `0x1000`, `recomp_runtime.cpp:238-239`) | task-6 §4.5; verified in the current tree |
| `HeapReAlloc` | **Heap exists, `HeapReAlloc` does not.** `win32_heap_alloc` walks a real free list (`recomp_runtime.cpp:240`), but `HeapReAlloc` is absent from `kShims` (verified) — this is a new function, not a rename | `runtime/recomp_runtime.cpp:240`, `:386` |
| `RaiseException`, `RtlUnwind` | **Policy, not code.** igi-recomp aborts; MSVC C++ exceptions need real dispatch. Decide abort-vs-continue once and mirror it in the reference | `shim/src/kernel32.c:250`, `:255` |
| `RtlCaptureContext`, `RtlLookupFunctionEntry`, `RtlVirtualUnwind`, `RtlUnwindEx` | **No `.pdata` parsing at all.** The PE layer parses sections, imports, exports, base relocations and TLS callbacks, but no data directories (`core/binary/pe.hpp:52-67`); `RtlLookupFunctionEntry`/`RtlVirtualUnwind` are defined against the exception directory (`RUNTIME_FUNCTION`), so this is new parser work plus three shims — and **igi-recomp has none of them** (only `RtlUnwind`) | `core/binary/pe.hpp:52-67`; igi-recomp shim inventory |
| `CreateWindowExA`, `DispatchMessageA`, `DefWindowProcA`, `GetMessageA`, `PeekMessageA`, `DirectDrawEnumerateExA`, `RegisterClassA`, `ShowWindow`, `DestroyWindow`, `SetWindowPos`, `InvalidateRect`, `UpdateWindow`, `SetForegroundWindow`, `GetForegroundWindow`, `GetClientRect`, `ClientToScreen`, `AdjustWindowRect`, `GetSystemMetrics`, `GetDC`, `ReleaseDC`, `LoadIconA`, `LoadCursorA`, `ShowCursor`, `MessageBoxA`, `SetWindowTextA`, `TranslateMessage`, `PostMessageA`, `PostQuitMessage`, `SetFocus`, `UnregisterClassA`, `GetWindowLongA`, `CreateICA`, `DeleteDC`, `GetDeviceCaps` | **No platform layer and no message loop.** These need a host window (`platform_create_window`), a pump (`platform_pump`/`platform_wait`), a message queue, and **re-entry into guest code** — igi-recomp's `send_message` calls the guest WndProc through `guest_call` (`shim/src/user32.c:63-69`), which igi.exe reaches via `CreateWindowExA` dispatching `WM_NCCREATE`/`WM_CREATE` (`shim/src/user32.c:158-159`). We have `invoke_guest_indirect` (`recomp_runtime.hpp:1372`) but no message loop | task-6 §4.4; `runtime/recomp_runtime.hpp:1372` |
| `DirectDrawCreateEx`, `DirectInputCreateA/Ex`, `DirectSoundCreate` (ordinal 1), `CoCreateInstance` | **No COM model and no renderer.** These hand the guest a vtable pointer into a host-built COM object (`com_vtable`/`com_new`, `shim/include/com.h`), and ddraw's object model pulls in `render_gl.c` (3186 lines), `render_backend.c` (1568), `d3d7.c` (1825) | task-6 §1, §7.2 |
| `AVIFileOpenA`, `AVIStreamRead`, `ICLocate`, `ICDecompress`, `ICSendMessage`, `ICClose` | **No AVI parser / codec.** `AVIFileOpenA` alone is 49 lines plus `parse_avi`; `ICDecompress` is 82 lines and optionally links libavcodec | `shim/src/avifil32.c:140`, `:398`; `CMakeLists.txt:184-194` |
| `shell32.dll!#25`, `shlwapi.dll!#12` (imgview64 only) | **Ordinal imports with no name.** Our parser names them `"#25"`/`"#12"` (`core/binary/pe.cpp:230`); identifying them needs the exporting DLL's export table, and our shim lookup is an exact string compare (`runtime/win32_abi.hpp:89-90`) | `core/binary/pe.cpp:230` |
| Everything reached via `GetProcAddress` | **Dynamic imports are a hidden surface.** Our `GetProcAddress` (`win32_get_proc_address`, `runtime/recomp_runtime.cpp:366-371`) looks the name up via `lookup_win32_import` (`:476`) and calls `terminate_with_message` if absent. imgview64 imports only 11 symbols, so its GDI+ calls must be resolved dynamically and will abort at `GetProcAddress` unless registered | `runtime/recomp_runtime.cpp:366-371`, `:476` |

---

## 5. Which applications still will not run after the first two batches

**All 16.** Batch 1 + Batch 2 leave every binary short of a complete import set, and none of them has a
reference-side model. Measured residual after Batches 1+2:

| binary | missing now | after Batch 1 | after Batches 1+2 |
| --- | --- | --- | --- |
| supertux2.exe | 710 | 708 | 708 |
| openlierox.exe | 618 | 616 | 611 |
| powder.exe | 544 | 539 | 536 |
| clipjar.exe | 344 | 335 | 330 |
| bat.exe | 251 | 242 | 242 |
| legacy-notepad-x64.exe | 173 | 161 | 160 |
| snake.exe | 140 | 140 | 140 |
| plink.exe | 109 | 95 | 87 |
| fd.exe | 100 | 86 | 86 |
| **igi.exe** | 97 | 83 | 64 |
| rg.exe | 84 | 70 | 70 |
| Pixeltetris.exe | 84 | 72 | 71 |
| Tetris.exe | 83 | 82 | 80 |
| **imgview64.exe** | 8 | 8 | **8** |
| luhn.exe (.NET) | 1 | 1 | 1 |
| TicTacToe.exe (.NET) | 1 | 1 | 1 |

Two things stand out and both should temper expectations:

- **imgview64.exe gains nothing from Batch 1 or 2.** Its only kernel32 gap is `VirtualProtect`, which
  igi-recomp does not implement; its other gaps are `comctl32!InitCommonControlsEx`,
  `gdiplus!GdiplusStartup`, `ole32!CoTaskMemFree`, `shell32!#25`, `shlwapi!#12`, `user32!GetDC`,
  `gdi32!DeleteDC`. The two it *does* get (`GetDC`, `DeleteDC`) are ranked 16 and 15 — i.e. in Batch 1's
  tail, not its head. imgview64 is the closest to a complete import set but the furthest from a
  rendering path.
- **snake.exe gains nothing either** — all 140 of its missing imports are the MSVC C++ runtime and the
  UCRT (`msvcp140.dll` 75, `api-ms-win-crt-runtime` 19, `api-ms-win-crt-stdio` 15, `vcruntime140` 11,
  …), none of which is Win32 and none of which igi-recomp implements.

**And after *all* 96 applicable shims** the residuals are: igi.exe **0**, imgview64 **6**, rg 70,
Pixeltetris 71, Tetris 80, plink 86, fd 86, snake 140, legacy-notepad 145, bat 241, clipjar 313,
powder 519, openlierox 609, supertux 708, luhn 1, TicTacToe 1. Only igi.exe closes, and only because
igi-recomp is a recompilation of that exact game.

---

## 6. Would any batch get a genuine application to `verify`? **No.**

Four independent blockers, each verified in the tree:

1. **The reference models 4 imports; the runtime has 63.** `emulate_shim` handles `GetStdHandle`,
   `WriteFile`, `ReadFile` and `ExitProcess` and nothing else
   (`core/verification/differential_harness.cpp:144`, `:147`, `:156`, `:162`); any other symbol sets
   `"reference does not model <lib>!<symbol>"` and stops the engine (`:173`), which makes
   `compare_project` report "reference execution did not complete" (`:335`). Porting a shim into the
   runtime therefore does **not** move `verify` at all — it only moves `run`. Every one of the 16
   applications calls imports beyond those four, so **`verify` aborts for all 16 today**, and it will
   keep aborting until each shim has a reference-side counterpart that produces identical results on a
   Unicorn engine (registers, guest memory writes, and any host state such as file handles).
2. **Import closure is not reachable for 15 of 16.** Only igi.exe reaches 0 missing after everything
   igi-recomp offers (§5). imgview64's remaining 6 are not in igi-recomp at all, two are unnamed
   ordinals, and one is GDI+.
3. **Even at 0 missing, igi.exe is not runnable yet.** It needs the platform layer: a handle table, a
   host window and message loop, DirectDraw/Direct3D 7, DirectSound, DirectInput, the AVI path — roughly
   6,000+ lines in igi-recomp (task-6 §7.2) — plus the load-time and runtime behaviour of `GetProcAddress`
   for the DirectX entry points. And it is a GUI game: its stdout is empty, so its `verify` would be a
   trace-only comparison, which is weaker than the documented contract (`README.md`, "Verification").
4. **imgview64 is a GUI app too.** GDI+/user32/comctl32 with two ordinal imports; its "output" is a
   window, not bytes. Even fully shimmed it would verify on an empty stdout plus a trace — and only if
   both sides render identically, which is a much larger claim than "the shim exists".

**What this means for the milestone.** Shim work cannot, on its own, produce a genuine application at
`verify`. It *can* produce a genuine application that **runs to `ExitProcess`** (`run`, not `verify`) —
and that is the honest first target. To get a genuine application to `verify` there are exactly two
routes:

- **Route A (recommended for the MVP claim):** keep the fixture-based `verify` as the correctness
  contract (it works today because fixtures only use the 4 modelled imports), and treat "first genuine
  application runs" as a separate, clearly-labelled milestone with its own evidence (exit code + trace
  length + a captured trace diff against the Unicorn reference where the reference can run).
- **Route B:** make the reference and the runtime share one shim implementation, so a shim is written
  once and `verify` scales with it. That is a design change, not a shim port: today the two sides have
  different substrates (a flat `guest_memory` array vs. a Unicorn engine), so a shared body needs an
  abstraction over "guest memory + registers". Until that exists, every shim costs two implementations
  and `verify` stays 4-symbol-deep.

---

## 7. Recommended execution order

1. **Batch 0 first, and keep it in the same commit as each shim:** decide the reference strategy
   (Route A or B, §6). Without it, `verify` cannot see any of the work in this plan.
2. **Batch 1a (9 shims, 10 binaries, no new infrastructure)** — the cheapest real reduction, and 8 of
   the 9 are literal renames. Ship it as one commit with its ABI rows.
3. **Add the Win32 handle table, then Batch 1b (5 shims, 12 binaries).** The handle table is the single
   highest-leverage piece of infrastructure in this plan: it unlocks 12 binaries in Batch 1b, 6 more in
   Batch 2, and it is a prerequisite for every file shim igi.exe needs.
4. **Then the on-demand loop for igi.exe** — because the loader binds every import to a thunk and only
   fails when an *unbound* thunk is called (`unbound_import_thunk`, `recomp_runtime.cpp:705`, bound at
   `:743`), the fastest route to "igi.exe runs" is: run it, read the address/name of the first unbound
   import, port that one shim, repeat. igi-recomp's bodies make each iteration minutes of work, and this
   avoids porting 97 shims to discover that the first 20 were the ones that mattered. It also tells us
   which of the 97 are *never executed* — the SEH trio and much of user32 may well be in that set.
5. **Only then the breadth batches** (2 → 5), and the platform layer for igi.exe (Batch 6), which is
   where the real remaining cost is.

**Do not** start with the W-variant/CRT batches (Batch 4/5): they are the largest *distinct-symbol*
counts in the census but they are fresh code, not adaptations, and they close no binary.

---

## 8. Unverified / not read

- I did not run any binary through `run` or `verify`; the "no batch reaches verify" conclusion is from
  reading `differential_harness.cpp` (reference model + fail-closed branches) and from the measured
  import sets, not from a failed run I observed myself.
- Whether the `Rtl*` trio actually **executes** in a non-throwing run is not established. Being
  "missing" is a binding gap (`imports` counts it), not proof of a runtime call; this is exactly why §7.4
  recommends the on-demand loop.
- `shell32.dll!#25` and `shlwapi.dll!#12` are unidentified — I did not resolve the ordinals against the
  exporting DLLs.
- The Batch 2/4/5 contents are indicative groupings of the ranked table; I did not read every one of
  those igi-recomp bodies line by line (Batch 1's 14 bodies *were* all read).
- Per-shim ABI `argument_count` values in §3 are taken from the `nargs` each igi-recomp body passes to
  `stdcall_ret`; they were not cross-checked against the Microsoft headers.
- Line numbers for `runtime/recomp_runtime.cpp` and `runtime/recomp_runtime.hpp` are as of the end of
  this task and will move — those files are being edited concurrently (they grew from 656 to 797 and
  44435 B to 1409 lines during it). The other files cited were stable.
